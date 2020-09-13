// NOLINT(legal/copyright)
/**@file
 * This header file is part of the utilities library; it contains the C++
 * interface for the fiber implementation.
 *
 * The design of the C++ interface is based on the <b>fiber</b> class in
 * <a href="https://www.boost.org/doc/libs/release/libs/context/doc/html/index.html">Boost.Context</a>.
 * It is a wrapper around `#fiber_t*` which tries to prevent accidentally
 * resuming a running or terminated fiber. The API is designed to be a building
 * block for higher level constructs. For example, a call/cc operator similar to
 * the one in Scheme can be implemented as:
 * ```{.cpp}
 * template <class F>
 * inline Fiber
 * callcc(F&& f) {
 *   return Fiber(::std::forward<F>(f)).resume();
 * }
 * ```
 *
 * @see lely/util/fiber.h
 *
 * @copyright 2018-2020 Lely Industries N.V.
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

#ifndef LELY_UTIL_FIBER_HPP_
#define LELY_UTIL_FIBER_HPP_

#include <lely/libc/type_traits.hpp>
#include <lely/util/error.hpp>
#include <lely/util/fiber.h>

#include <utility>

namespace lely {
namespace util {

#if __cpp_exceptions

class Fiber;

namespace detail {

struct FiberData {
  bool terminated{false};
  bool unwind{false};
  ::std::exception_ptr eptr{nullptr};
};

}  // namespace detail

/**
 * Convenience class providing a RAII-style mechanism to ensure the fiber
 * associated with the calling thread is intialized for the duration of a scoped
 * block.
 */
class FiberThread {
  friend class Fiber;

 public:
  /**
   * Initializes the fiber associated with the calling thread, if it was not
   * already initialized.
   */
  FiberThread() : FiberThread(fiber_attr FIBER_ATTR_INIT) {}

  /**
   * Initializes the fiber associated with the calling thread, if it was not
   * already initialized.
   *
   * @param attr the fiber attributes.
   */
  explicit FiberThread(const fiber_attr& attr) {
    if (fiber_thrd_init(&attr) == -1) throw_errc("FiberThread");
  }

  /**
   * Initializes the fiber associated with the calling thread, if it was not
   * already initialized.
   *
   * @param attr    the fiber attributes.
   * @param already set to true if the fiber associated with the calling thread
   *                was already initialized, and to false if not. In the former
   *                case, the value of <b>flags</b> is ignored.
   */
  explicit FiberThread(const fiber_attr& attr, bool& already) {
    int result = fiber_thrd_init(&attr);
    if (result == -1) throw_errc("FiberThread");
    already = result != 0;
  }

  FiberThread(const FiberThread&) = delete;
  FiberThread(FiberThread&&) = delete;

  FiberThread& operator=(const FiberThread&) = delete;
  FiberThread& operator=(FiberThread&&) = delete;

  /**
   * Finalizes the fiber associated with the calling thread, unless another
   * instance of this class is still in scope.
   */
  ~FiberThread() { fiber_thrd_fini(); }

 private:
  static detail::FiberData*
  data_() noexcept {
#if LELY_NO_THREADS
    static detail::FiberData data_;
#else
    static thread_local detail::FiberData data_;
#endif
    return &data_;
  }
};

/// A fiber. @see fiber_t
class Fiber {
 public:
  /**
   * Creates an invalid fiber.
   *
   * @post #operator bool() returns false.
   */
  Fiber() noexcept = default;

  Fiber(const Fiber&) = delete;

  /**
   * Moves the state of <b>other</b> to `*this`.
   *
   * @post <b>other</b> is an invalid fiber (#operator bool() returns false).
   */
  Fiber(Fiber&& other) noexcept { swap(other); }

  explicit Fiber(fiber_t* fiber) noexcept : fiber_(fiber) {}

  /**
   * Constructs a fiber with the default attributes. The specified callable
   * object is not invoked until the first call to resume() or resume_with().
   */
  template <class F, class = typename ::std::enable_if<!::std::is_same<
                         typename ::std::decay<F>::type, Fiber>::value>::type>
  explicit Fiber(F&& f)
      : Fiber(::std::forward<F>(f), fiber_attr FIBER_ATTR_INIT) {}

  /**
   * Constructs a fiber with the specified attributes. The specified callable
   * object is not invoked until the first call to resume() or resume_with().
   *
   * @param f    a callable object with signature `Fiber(Fiber&&)`.
   * @param attr the fiber attributes.
   */
  template <class F, class = typename ::std::enable_if<compat::is_invocable_r<
                         Fiber, F, Fiber&&>::value>::type>
  Fiber(F&& f, const fiber_attr& attr) {
    if (attr.data_size || attr.data_addr)
      throw_error_code("Fiber", ::std::errc::invalid_argument);
    fiber_attr attr_ = attr;
    attr_.data_size = sizeof(detail::FiberData);
    fiber_ = fiber_create(&attr_, &func_<decltype(f)>,
                          static_cast<void*>(::std::addressof(f)));
    if (!fiber_) throw_errc("Fiber");
    auto data = data_(fiber_);
    // The default constructor for detail::FiberData does not throw.
    new (data) detail::FiberData();
    // The first call to func_() is guaranteed to not throw.
    *this = ::std::move(*this).resume();
    // Handle the exception thrown by the fiber.
    auto eptr = data->eptr;
    if (eptr) {
      this->~Fiber();
      ::std::rethrow_exception(eptr);
    }
  }

  Fiber& operator=(const Fiber&) = delete;

  /**
   * Moves the state of <b>other</b> to `*this`.
   *
   * @post <b>other</b> is an invalid fiber (#operator bool() returns false).
   *
   * @returns `*this`.
   */
  Fiber&
  operator=(Fiber&& other) noexcept {
    swap(other);
    return *this;
  }

  /**
   * Destroys a #Fiber instance. If the instance represents a fiber of execution
   * (#operator bool() returns true), then the fiber of execution is destroyed
   * also. If the callable object with which the fiber was created has not yet
   * terminated, its stack is unwound as if by
   * ```{.cpp}
   * ::std::move(*this).resume_with([](Fiber&& f) -> Fiber {
   *   throw fiber_unwind(::std::move(f));
   *   return {};
   * });
   * ```
   * To ensure proper destruction, the callable MUST NOT catch the
   * #lely::util::fiber_unwind exception (or rethrow it if it does).
   */
  ~Fiber() {
    if (fiber_) {
      auto data = data_(fiber_);
      if (data) {
        if (!data->terminated) {
          data->unwind = true;
          *this = ::std::move(*this).resume();
        }
        data->~FiberData();
        fiber_destroy(fiber_);
      }
    }
  }

  /// Checks whether `*this` is a valid fiber.
  explicit operator bool() const noexcept { return fiber_ != nullptr; }

  operator fiber_t*() && noexcept {
    fiber_t* tmp = fiber_;
    fiber_ = nullptr;
    return tmp;
  }

  /**
   * Suspends the calling fiber and resumes `*this`. If `*this` is an invalid
   * fiber (#operator bool() returns false), the fiber associated with the
   * calling thread is resumed.
   *
   * @returns the fiber that has been suspended in order to resume the current
   * fiber.
   *
   * @pre the calling thread is the thread on which `*this` was created.
   * @post `*this` is an invalid fiber (#operator bool() returns false).
   * @throw fiber_unwind if the fiber is being destroyed. This exception MUST
   * NOT be caught (or rethrown if it is).
   */
  Fiber
  resume() && {
    return resume_(Fiber(fiber_resume(::std::move(*this))));
  }

  /**
   * Suspends the calling fiber and resumes `*this`, but calls <b>f(other)</b>
   * in the resumed fiber as if called by the suspended callable object, where
   * <b>other</b> is the fiber that has been suspended in order to resume the
   * current fiber. If `*this` is an invalid fiber (#operator bool() returns
   * false), the fiber associated with the calling thread is resumed.
   *
   * @returns the result of <b>f()</b>.
   *
   * @pre the calling thread is the thread on which `*this` was created.
   * @post `*this` is an invalid fiber (#operator bool() returns false).
   * @throw fiber_unwind if the fiber is being destroyed. This exception MUST
   * NOT be caught (or rethrown if it is).
   */
  template <class F>
  Fiber
  resume_with(F&& f) && {
    auto func = [](fiber_t* fiber, void* arg) noexcept {
      Fiber f(fiber);
      try {
        f = (*static_cast<F*>(arg))(::std::move(f));
      } catch (...) {
        auto data = data_();
        if (!data) data = FiberThread::data_();
        data->eptr = ::std::current_exception();
      }
      return static_cast<fiber_t*>(::std::move(f));
    };
    auto arg = static_cast<void*>(::std::addressof(f));
    return resume_(Fiber(fiber_resume_with(::std::move(*this), func, arg)));
  }

  /// Swaps the states of `*this` and <b>other</b>.
  void
  swap(Fiber& other) noexcept {
    using ::std::swap;
    swap(fiber_, other.fiber_);
  }

 private:
  template <class F>
  static fiber_t* func_(fiber_t* fiber, void* arg) noexcept;

  static detail::FiberData*
  data_(fiber_t* fiber = nullptr) noexcept {
    return static_cast<detail::FiberData*>(fiber_data(fiber));
  }

  Fiber resume_(Fiber&& f);

  fiber_t* fiber_{nullptr};
};

/**
 * The exception used by #lely::util::Fiber::~Fiber() to terminate the callable
 * object and unwind its stack.
 */
class fiber_unwind {
  friend class Fiber;

 public:
  fiber_unwind() noexcept = default;

  explicit fiber_unwind(Fiber&& f) noexcept : f_(::std::move(f)) {}

 private:
  Fiber f_;
};

template <class F>
fiber_t*
Fiber::func_(fiber_t* fiber, void* arg) noexcept {
  auto data = data_();
  try {
    // Copy the function to be executed to the stack for later reference.
    using F_ = typename ::std::decay<F>::type;
    F_ func{::std::forward<F_>(static_cast<F>(*static_cast<F_*>(arg)))};
    // Return to the constructor.
    Fiber f(fiber_resume(fiber));
    fiber = nullptr;
    try {
      // Rethrow the exception thrown the function passed to resume_with(), if
      // any.
      if (data->eptr) ::std::rethrow_exception(data->eptr);
      // Invoke the function, unless the fiber is being destroyed.
      if (!data->unwind) f = func(::std::move(f));
    } catch (fiber_unwind& e) {
      f = ::std::move(e.f_);
    }
    data->terminated = true;
    return ::std::move(f);
  } catch (...) {
    if (fiber) {
      // An exception was thrown while copying the function. Store it and return
      // to the constructor of the fiber.
      data->eptr = ::std::current_exception();
      return fiber;
    }
    // Similar to threads, exceptions thrown by a fiber function will result in
    // termination.
    ::std::terminate();
  }
}

inline Fiber
Fiber::resume_(Fiber&& f) {
  auto data = data_();
  if (!data) data = FiberThread::data_();
  if (data) {
    // Store the exception thrown by the function passed to resume_with(), if
    // any, and clear it, so it does not get thrown again on the next call to
    // resume().
    auto eptr = data->eptr;
    data->eptr = nullptr;
    // Termination takes precedence over any exception.
    if (data->unwind) throw fiber_unwind(::std::move(f));
    if (eptr) ::std::rethrow_exception(eptr);
  }
  return ::std::move(f);
}

#endif  // __cpp_exceptions

}  // namespace util
}  // namespace lely

#endif  // !LELY_UTIL_FIBER_HPP_
