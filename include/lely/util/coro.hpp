/**@file
 * This header file is part of the utilities library; it contains the C++
 * interface for the asymmetric coroutine implementation.
 *
 * @see lely/util/coro.h
 *
 * @copyright 2020 Lely Industries N.V.
 *
 * @author J. S. Seldenthuis <jseldenthuis@lely.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LELY_UTIL_CORO_HPP_
#define LELY_UTIL_CORO_HPP_

#include <lely/libc/type_traits.hpp>
#include <lely/util/chrono.hpp>
#include <lely/util/coro.h>
#include <lely/util/error.hpp>
#include <lely/util/exception.hpp>
#include <lely/util/invoker.hpp>
#include <lely/util/mutex.hpp>
#include <lely/util/stop.hpp>

#include <exception>
#include <utility>

namespace lely {
namespace util {

/**
 * Convenience class providing a RAII-style mechanism to ensure the fiber
 * associated with the calling thread is intialized for the duration of a scoped
 * block.
 */
class CoroutineThread {
  friend class Fiber;

 public:
  /**
   * Initializes the coroutine associated with the calling thread, if it was not
   * already initialized.
   */
  CoroutineThread() : CoroutineThread(coro_attr CORO_ATTR_INIT) {}

  /**
   * Initializes the coroutine associated with the calling thread, if it was not
   * already initialized, as well as the coroutine scheduler for the thread.
   *
   * @param attr the coroutine attributes.
   * @param ctor a pointer to the factory used to create, and later destroy, the
   *             coroutine scheduler for the calling thread. If <b>ctor</b> is
   *             a null pointer, a default (round-robin) scheduler is used.
   */
  explicit CoroutineThread(const coro_attr& attr,
                           coro_sched_ctor_t* ctor = nullptr) {
    if (coro_thrd_init(&attr, ctor) == -1) throw_errc("CoroutineThread");
  }

  /**
   * Initializes the coroutine associated with the calling thread, if it was not
   * already initialized, as well as the coroutine scheduler for the thread.
   *
   * @param attr    the coroutine attributes.
   * @param ctor    a pointer to the factory used to create, and later destroy,
   *                the coroutine scheduler for the calling thread. If
   *                <b>ctor</b> is a null pointer, a default (round-robin)
   *                scheduler is used.
   * @param already set to true if the coroutine associated with the calling
   *                thread was already initialized, and to false if not. In the
   *                former case, the attributes are ignored.
   */
  explicit CoroutineThread(const coro_attr& attr, coro_sched_ctor_t* ctor,
                           bool& already) {
    int result = coro_thrd_init(&attr, ctor);
    if (result == -1) throw_errc("CoroutineThread");
    already = result != 0;
  }

  CoroutineThread(const CoroutineThread&) = delete;
  CoroutineThread(CoroutineThread&&) = delete;

  CoroutineThread& operator=(const CoroutineThread&) = delete;
  CoroutineThread& operator=(CoroutineThread&&) = delete;

  /**
   * Finalizes the coroutine associated with the calling thread, unless another
   * instance of this class is still in scope.
   */
  ~CoroutineThread() { coro_thrd_fini(); }
};

/// An asymmetric coroutine.
class Coroutine {
 public:
  /// A unique identifier for a coroutine.
  class id {
   public:
    id() = default;

    id(const id&) = default;

    id(id&& other) noexcept : coro_(other.coro_) { other.coro_ = nullptr; }

    explicit id(coro_t coro) noexcept : coro_(coro) {}

    id& operator=(const id&) = default;

    id&
    operator=(id&& other) noexcept {
      if (this != &other) {
        coro_ = other.coro_;
        other.coro_ = nullptr;
      }
      return *this;
    }

    operator coro_t() const noexcept { return coro_; }

   private:
    coro_t coro_{coro_t()};
  };

  using native_handle_type = coro_t;

  /// Constructs an object that does not represent a thread of execution.
  Coroutine() = default;

  Coroutine(const Coroutine&) = delete;

  Coroutine(Coroutine&& other) noexcept
      : source_(::std::move(other.source_)), id_(::std::move(other.id_)) {}

  /// @see coro_create()
  template <
      class F, class... Args,
      typename ::std::enable_if<
          !::std::is_same<typename ::std::decay<F>::type, Coroutine>::value &&
              !::std::is_convertible<typename ::std::decay<F>::type,
                                     const coro_attr&>::value &&
              !::std::is_convertible<typename ::std::decay<F>::type,
                                     const coro_attr*>::value,
          int>::type = 0>
  explicit Coroutine(F&& f, Args&&... args)
      : Coroutine(nullptr, ::std::forward<F>(f), std::forward<Args>(args)...) {}

  /// @see coro_create()
  template <class F, class... Args>
  explicit Coroutine(const coro_attr& attr, F&& f, Args&&... args)
      : Coroutine(&attr, ::std::forward<F>(f), std::forward<Args>(args)...) {}

  Coroutine& operator=(const Coroutine&) = delete;

  /**
   * If joinable(), calls request_stop() followed by join(). Then assigns the
   * identifier of <b>other</b> to
   * `*this` and sets <b>other</b> to the default constructed state.
   */
  Coroutine&
  operator=(Coroutine&& other) noexcept {
    if (this != &other) {
      if (joinable()) {
        request_stop();
        join();
      }

      source_ = ::std::move(other.source_);
      id_ = ::std::move(other.id_);
    }
    return *this;
  }

  /**
   * If joinable(), calls request_stop() and then by join(). Otherise, has no
   * effects.
   */
  ~Coroutine() {
    if (joinable()) {
      request_stop();
      join();
    }
  }

  /**
   * Checks whether `*this` represents a valid coroutine that has not been
   * detached or joined.
   */
  bool
  joinable() const noexcept {
    return id_ != id() && id_ != id(coro_current());
  }

  /// Returns the coroutine identifier for `*this`.
  id
  get_id() noexcept {
    return id_;
  }

  /// @see coro_join()
  void
  join() {
    if (coro_join(native_handle(), nullptr) != coro_success)
      util::throw_errc("join");
    id_ = id();
  }

  /// @see coro_detach()
  void
  detach() {
    if (coro_detach(native_handle()) != coro_success)
      util::throw_errc("detach");
    id_ = id();
  }

  StopSource
  get_stop_source() const noexcept {
    return source_;
  }

  StopToken
  get_stop_token() const noexcept {
    return source_.get_token();
  }

  bool
  request_stop() noexcept {
    return source_.request_stop();
  }

  native_handle_type
  native_handle() noexcept {
    return id_;
  }

 private:
  template <class F, class... Args,
            typename ::std::enable_if<compat::is_invocable<F, Args...>::value,
                                      int>::type = 0>
  explicit Coroutine(const coro_attr* attr, F&& f, Args&&... args)
      : source_(nullptr),
        id_(make_coro_(attr, ::std::forward<F>(f),
                       ::std::forward<Args>(args)...)) {}

  template <
      class F, class... Args,
      typename ::std::enable_if<
          compat::is_invocable<F, StopToken, Args...>::value, int>::type = 0>
  explicit Coroutine(const coro_attr* attr, F&& f, Args&&... args)
      : source_(StopSource()),
        id_(make_coro_(attr, ::std::forward<F>(f), get_stop_token(),
                       ::std::forward<Args>(args)...)) {}

  template <class F, class... Args>
  static coro_t
  make_coro_(const coro_attr* attr, F&& f, Args&&... args) {
    using invoker_type = invoker_t<F, Args...>;
    auto invoker =
        new invoker_type(::std::forward<F>(f), ::std::forward<Args>(args)...);
    native_handle_type coro;
    if (coro_create(
            &coro, attr,
            [](void* arg) noexcept {
              auto invoker = static_cast<invoker_type*>(arg);
              (*invoker)();
              delete invoker;
              return 0;
            },
            invoker) != coro_success) {
      delete invoker;
      util::throw_errc("Coroutine");
    }
    return coro;
  }

  StopSource source_;
  id id_;
};

inline bool
operator==(Coroutine::id lhs, Coroutine::id rhs) noexcept {
  return static_cast<coro_t>(lhs) == static_cast<coro_t>(rhs);
}

inline bool
operator!=(Coroutine::id lhs, Coroutine::id rhs) noexcept {
  return !(lhs == rhs);
}

inline bool
operator<(Coroutine::id lhs, Coroutine::id rhs) noexcept {
  return static_cast<coro_t>(lhs) < static_cast<coro_t>(rhs);
}

inline bool
operator<=(Coroutine::id lhs, Coroutine::id rhs) noexcept {
  return !(rhs < lhs);
}

inline bool
operator>(Coroutine::id lhs, Coroutine::id rhs) noexcept {
  return rhs < lhs;
}

inline bool
operator>=(Coroutine::id lhs, Coroutine::id rhs) noexcept {
  return !(lhs < rhs);
}

/// Provides functions that access the currently running coroutine.
namespace this_coro {

/// @see coro_yield()
inline void
yield() noexcept {
  coro_yield();
}

/// @see coro_current()
inline Coroutine::id
get_id() noexcept {
  return Coroutine::id(coro_current());
}

/// @see coro_sleep()
template <class Rep, class Period>
inline void
sleep_for(const ::std::chrono::duration<Rep, Period>& sleep_duration) {
  auto duration = to_timespec(sleep_duration);
  if (coro_sleep(&duration, nullptr) < -1) util::throw_errc("sleep_for");
}

/// @see coro_sleep()
template <class Clock, class Duration>
void
sleep_until(const ::std::chrono::time_point<Clock, Duration>& sleep_time) {
  sleep_for(sleep_time - Clock::now());
}

}  // namespace this_coro

namespace detail {

inline void
throw_coroutine_error(const char* what_arg, int ev) {
  switch (ev) {
    case coro_success:
      break;
    case coro_error:
      util::throw_errc(what_arg);
    case coro_timedout:
      throw_or_abort(::std::system_error(
          ::std::make_error_code(::std::errc::timed_out), what_arg));
    case coro_busy:
      throw_or_abort(::std::system_error(
          ::std::make_error_code(::std::errc::resource_unavailable_try_again),
          what_arg));
    case coro_nomem:
      throw_or_abort(::std::system_error(
          ::std::make_error_code(::std::errc::not_enough_memory), what_arg));
  }
}

/// The base class for mutexes suitable for use in coroutines.
class CoroutineMutexBase {
 public:
  using native_handle_type = coro_mtx_t*;

  CoroutineMutexBase() = default;

  CoroutineMutexBase(const CoroutineMutexBase&) = delete;
  CoroutineMutexBase(CoroutineMutexBase&& other) = delete;

  CoroutineMutexBase& operator=(const CoroutineMutexBase&) = delete;
  CoroutineMutexBase& operator=(CoroutineMutexBase&& other) = delete;

  ~CoroutineMutexBase() { coro_mtx_destroy(native_handle()); }

  operator coro_mtx_t*() noexcept { return &mtx_; }

  /// @see coro_mtx_lock()
  void
  lock() {
    int ev = coro_mtx_lock(native_handle());
    if (ev != coro_success) detail::throw_coroutine_error("lock", ev);
  }

  /// @see coro_mtx_trylock()
  bool
  try_lock() {
    int ev = coro_mtx_trylock(native_handle());
    switch (ev) {
      case coro_success:
        return true;
      case coro_busy:
        return false;
      default:
        detail::throw_coroutine_error("try_lock", ev);
        return false;
    }
  }

  /// @see coro_mtx_unlock()
  void
  unlock() {
    int ev = coro_mtx_unlock(native_handle());
    if (ev != coro_success) detail::throw_coroutine_error("unlock", ev);
  }

  native_handle_type
  native_handle() noexcept {
    return &mtx_;
  }

 private:
  coro_mtx_t mtx_{nullptr};
};

}  // namespace detail

/// A plain mutex suitable for use in coroutines.
class CoroutineMutex : public detail::CoroutineMutexBase {
 public:
  CoroutineMutex() {
    int ev = coro_mtx_init(native_handle(), coro_mtx_plain);
    if (ev != coro_success) detail::throw_coroutine_error("CoroutineMutex", ev);
  }
};

/// A timed mutex suitable for use in coroutines.
class CoroutineTimedMutex : public detail::CoroutineMutexBase {
 public:
  CoroutineTimedMutex() {
    int ev = coro_mtx_init(native_handle(), coro_mtx_timed);
    if (ev != coro_success)
      detail::throw_coroutine_error("CoroutineTimedMutex", ev);
  }

  /// @see coro_mtx_timedlock()
  template <class Rep, class Period>
  bool
  try_lock_for(const std::chrono::duration<Rep, Period>& rel_time) {
    return try_lock_until(::std::chrono::system_clock::now() + rel_time);
  }

  /// @see coro_mtx_timedlock()
  template <class Clock, class Duration>
  bool
  try_lock_until(const std::chrono::time_point<Clock, Duration>& abs_time) {
    const auto ts = util::to_timespec(
        compat::clock_cast<::std::chrono::system_clock>(abs_time));
    return coro_mtx_timedlock(native_handle(), &ts) == coro_success;
  }
};

/// A recursive mutex suitable for use in coroutines.
class CoroutineRecursiveMutex : public detail::CoroutineMutexBase {
 public:
  CoroutineRecursiveMutex() {
    int ev = coro_mtx_init(native_handle(), coro_mtx_recursive);
    if (ev != coro_success)
      detail::throw_coroutine_error("CoroutineRecursiveMutex", ev);
  }
};

/// A timed and recursive mutex suitable for use in coroutines.
class CoroutineTimedRecursiveMutex : public detail::CoroutineMutexBase {
 public:
  CoroutineTimedRecursiveMutex() {
    int ev =
        coro_mtx_init(native_handle(), coro_mtx_timed | coro_mtx_recursive);
    if (ev != coro_success)
      detail::throw_coroutine_error("CoroutineRecursiveMutex", ev);
  }

  /// @see coro_mtx_timedlock()
  template <class Rep, class Period>
  bool
  try_lock_for(const std::chrono::duration<Rep, Period>& rel_time) {
    return try_lock_until(::std::chrono::system_clock::now() + rel_time);
  }

  /// @see coro_mtx_timedlock()
  template <class Clock, class Duration>
  bool
  try_lock_until(const std::chrono::time_point<Clock, Duration>& abs_time) {
    const auto ts = util::to_timespec(
        compat::clock_cast<::std::chrono::system_clock>(abs_time));
    return coro_mtx_timedlock(native_handle(), &ts) == coro_success;
  }
};

enum class cv_status { no_timeout, timeout };

/// A condition variable suitable for use in coroutines.
class CoroutineConditionVariable {
 public:
  using native_handle_type = coro_cnd_t*;

  CoroutineConditionVariable() {
    if (coro_cnd_init(native_handle()) != coro_success)
      ::lely::util::throw_errc("CoroutineConditionVariable");
  }

  CoroutineConditionVariable(const CoroutineConditionVariable&) = delete;
  CoroutineConditionVariable(CoroutineConditionVariable&& other) = delete;

  CoroutineConditionVariable& operator=(const CoroutineConditionVariable&) =
      delete;
  CoroutineConditionVariable& operator=(CoroutineConditionVariable&& other) =
      delete;

  ~CoroutineConditionVariable() { coro_cnd_destroy(native_handle()); }

  /// @see coro_cnd_signal()
  void
  notify_one() noexcept {
    coro_cnd_signal(native_handle());
  }

  /// @see coro_cnd_broadcast()
  void
  notify_all() noexcept {
    coro_cnd_broadcast(native_handle());
  }

  /// @see coro_cnd_wait()
  void
  wait(::std::unique_lock<CoroutineMutex>& lock) {
    int ev = coro_cnd_wait(native_handle(), lock.mutex()->native_handle());
    if (ev != coro_success) detail::throw_coroutine_error("wait", ev);
  }

  /// @see coro_cnd_wait()
  template <class Predicate>
  void
  wait(::std::unique_lock<CoroutineMutex>& lock, Predicate pred) {
    while (!pred()) wait(lock);
  }

  /// @see coro_cnd_timedwait()
  template <class Clock, class Duration>
  cv_status
  wait_until(::std::unique_lock<CoroutineMutex>& lock,
             const std::chrono::time_point<Clock, Duration>& abs_time) {
    const auto ts = util::to_timespec(
        compat::clock_cast<::std::chrono::system_clock>(abs_time));
    return coro_cnd_timedwait(native_handle(), lock.mutex()->native_handle(),
                              &ts) == coro_timedout
               ? cv_status::timeout
               : cv_status::no_timeout;
  }

  /// @see coro_cnd_timedwait()
  template <class Clock, class Duration, class Predicate>
  bool
  wait_until(::std::unique_lock<CoroutineMutex>& lock,
             const ::std::chrono::time_point<Clock, Duration>& abs_time,
             Predicate pred) {
    while (!pred()) {
      if (wait_until(lock, abs_time) == cv_status::timeout) return pred();
    }
    return true;
  }

  /// @see coro_cnd_timedwait()
  template <class Rep, class Period>
  cv_status
  wait_for(::std::unique_lock<CoroutineMutex>& lock,
           const ::std::chrono::duration<Rep, Period>& rel_time) {
    return wait_until(lock, ::std::chrono::system_clock::now() + rel_time);
  }

  /// @see coro_cnd_timedwait()
  template <class Rep, class Period, class Predicate>
  bool
  wait_for(::std::unique_lock<CoroutineMutex>& lock,
           const ::std::chrono::duration<Rep, Period>& rel_time,
           Predicate pred) {
    return wait_until(lock, ::std::chrono::system_clock::now() + rel_time,
                      ::std::move(pred));
  }

  native_handle_type
  native_handle() noexcept {
    return &cond_;
  }

 private:
  coro_cnd_t cond_{nullptr};
};

/**
 * A generalization of #lely::util::CoroutineConditionVariable capable of
 * operating on any lock that meets the BasicLockable requirements.
 */
class CoroutineConditionVariableAny {
 public:
  CoroutineConditionVariableAny() = default;

  CoroutineConditionVariableAny(const CoroutineConditionVariableAny&) = delete;
  CoroutineConditionVariableAny(CoroutineConditionVariableAny&& other) = delete;

  CoroutineConditionVariableAny& operator=(
      const CoroutineConditionVariableAny&) = delete;
  CoroutineConditionVariableAny& operator=(
      CoroutineConditionVariableAny&& other) = delete;

  ~CoroutineConditionVariableAny() = default;

  /// @see coro_cnd_signal()
  void
  notify_one() noexcept {
    ::std::lock_guard<CoroutineMutex> lock(mtx_);
    cond_.notify_one();
  }

  /// @see coro_cnd_broadcast()
  void
  notify_all() noexcept {
    ::std::lock_guard<CoroutineMutex> lock(mtx_);
    cond_.notify_all();
  }

  /// @see coro_cnd_wait()
  template <class Lock>
  void
  wait(Lock& lock) {
    ::std::unique_lock<CoroutineMutex> lock1(mtx_);
    UnlockGuard<Lock> unlock(lock);
    ::std::unique_lock<CoroutineMutex> lock2(::std::move(lock1));
    cond_.wait(lock2);
  }

  /// @see coro_cnd_wait()
  template <class Lock, class Predicate>
  void
  wait(Lock& lock, Predicate pred) {
    while (!pred()) wait(lock);
  }

  /// @see coro_cnd_timedwait()
  template <class Lock, class Clock, class Duration>
  cv_status
  wait_until(Lock& lock,
             const std::chrono::time_point<Clock, Duration>& abs_time) {
    ::std::unique_lock<CoroutineMutex> lock1(mtx_);
    UnlockGuard<Lock> unlock(lock);
    ::std::unique_lock<CoroutineMutex> lock2(::std::move(lock1));
    return cond_.wait_until(lock2, abs_time);
  }

  /// @see coro_cnd_timedwait()
  template <class Lock, class Clock, class Duration, class Predicate>
  bool
  wait_until(Lock& lock,
             const std::chrono::time_point<Clock, Duration>& abs_time,
             Predicate pred) {
    while (!pred()) {
      if (wait_until(lock, abs_time) == cv_status::timeout) return pred();
    }
    return true;
  }

  /// @see coro_cnd_timedwait()
  template <class Rep, class Period>
  cv_status
  wait_for(::std::unique_lock<CoroutineMutex>& lock,
           const ::std::chrono::duration<Rep, Period>& rel_time) {
    return wait_until(lock, ::std::chrono::system_clock::now() + rel_time);
  }

  /// @see coro_cnd_timedwait()
  template <class Rep, class Period, class Predicate>
  bool
  wait_for(::std::unique_lock<CoroutineMutex>& lock,
           const ::std::chrono::duration<Rep, Period>& rel_time,
           Predicate pred) {
    return wait_until(lock, ::std::chrono::system_clock::now() + rel_time,
                      ::std::move(pred));
  }

 private:
  CoroutineConditionVariable cond_;
  CoroutineMutex mtx_;
};

}  // namespace util
}  // namespace lely

#endif  // !LELY_UTIL_CORO_HPP_
