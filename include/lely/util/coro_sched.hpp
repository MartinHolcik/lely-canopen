/**@file
 * This header file is part of the utilities library; it contains the C++
 * interface for the coroutine scheduler and scheduler factory.
 *
 * @see lely/util/coro_sched.h
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

#ifndef LELY_UTIL_CORO_SCHED_HPP_
#define LELY_UTIL_CORO_SCHED_HPP_

#include <lely/util/coro_sched.h>
#include <lely/util/chrono.hpp>

namespace lely {
namespace util {

class BasicoroutineSchedulerFactory;

namespace detail {

struct CoroutineSchedulerVtable {
  const coro_sched_vtbl* vtbl;
};

}  // namespace detail

class BasicCoroutineScheduler : private detail::CoroutineSchedulerVtable {
  friend class BasicoroutineSchedulerFactory;

 public:
  using time_point = ::std::chrono::system_clock::time_point;

  BasicCoroutineScheduler() noexcept : CoroutineSchedulerVtable{&vtbl_} {}

  virtual ~BasicCoroutineScheduler() = default;

  operator coro_sched_t*() const noexcept { return &vtbl; }

  /// @see coro_sched_push()
  virtual void push(coro_t coro) noexcept = 0;

  /// @see coro_sched_pop()
  virtual coro_t pop() noexcept = 0;

  /// @see coro_sched_wait()
  virtual void wait() noexcept = 0;

  /// @see coro_sched_wait()
  virtual void wait_until(const time_point& abs_time) noexcept = 0;

  /// @see coro_sched_signal()
  virtual void signal() noexcept = 0;

 private:
  static void
  push_(coro_sched_t* sched, coro_t coro) noexcept {
    auto self = const_cast<BasicCoroutineScheduler*>(
        static_cast<const BasicCoroutineScheduler*>(
            reinterpret_cast<const detail::CoroutineSchedulerVtable*>(sched)));
    self->push(coro);
  }

  static coro_t
  pop_(coro_sched_t* sched) noexcept {
    auto self = const_cast<BasicCoroutineScheduler*>(
        static_cast<const BasicCoroutineScheduler*>(
            reinterpret_cast<const detail::CoroutineSchedulerVtable*>(sched)));
    return self->pop();
  }

  static void
  wait_(coro_sched_t* sched, const timespec* ts) noexcept {
    auto self = const_cast<BasicCoroutineScheduler*>(
        static_cast<const BasicCoroutineScheduler*>(
            reinterpret_cast<const detail::CoroutineSchedulerVtable*>(sched)));
    if (ts)
      self->wait_until(time_point(from_timespec(*ts)));
    else
      self->wait();
  }

  static void
  signal_(coro_sched_t* sched) noexcept {
    auto self = const_cast<BasicCoroutineScheduler*>(
        static_cast<const BasicCoroutineScheduler*>(
            reinterpret_cast<const detail::CoroutineSchedulerVtable*>(sched)));
    self->signal();
  }

  static constexpr coro_sched_vtbl vtbl_ = {
      &BasicCoroutineScheduler::push_,
      &BasicCoroutineScheduler::pop_,
      &BasicCoroutineScheduler::wait_,
      &BasicCoroutineScheduler::signal_,
  };
};

namespace detail {

struct CoroutineSchedulerFactoryVtable {
  const coro_sched_ctor_vtbl* vtbl;
};

}  // namespace detail

class BasicoroutineSchedulerFactory
    : private detail::CoroutineSchedulerFactoryVtable {
 public:
  BasicoroutineSchedulerFactory() noexcept
      : CoroutineSchedulerFactoryVtable{&vtbl_} {}

  virtual ~BasicoroutineSchedulerFactory() = default;

  operator coro_sched_ctor_t*() const noexcept { return &vtbl; }

  /// @see coro_sched_create()
  virtual BasicCoroutineScheduler* construct() = 0;

  /// @see coro_sched_destroy()
  virtual void destroy(BasicCoroutineScheduler* sched) noexcept;

 private:
  static coro_sched_t*
  create_(coro_sched_ctor_t* ctor) noexcept {
    auto self = const_cast<BasicoroutineSchedulerFactory*>(
        static_cast<const BasicoroutineSchedulerFactory*>(
            reinterpret_cast<const detail::CoroutineSchedulerFactoryVtable*>(
                ctor)));
#if __cpp_exceptions
    try {
      auto sched = self->construct();
      return sched ? static_cast<coro_sched_t*>(*sched) : nullptr;
#endif
#if __cpp_exceptions
    } catch (...) {
      return nullptr;
    }
#endif
  }

  static void
  destroy_(coro_sched_ctor_t* ctor, coro_sched_t* sched) noexcept {
    auto self = const_cast<BasicoroutineSchedulerFactory*>(
        static_cast<const BasicoroutineSchedulerFactory*>(
            reinterpret_cast<const detail::CoroutineSchedulerFactoryVtable*>(
                ctor)));
    self->destroy(const_cast<BasicCoroutineScheduler*>(
        static_cast<const BasicCoroutineScheduler*>(
            reinterpret_cast<const detail::CoroutineSchedulerVtable*>(sched))));
  }

  static constexpr coro_sched_ctor_vtbl vtbl_ = {
      &BasicoroutineSchedulerFactory::create_,
      &BasicoroutineSchedulerFactory::destroy_};
};

inline void
BasicoroutineSchedulerFactory::destroy(
    BasicCoroutineScheduler* sched) noexcept {
  delete sched;
}

}  // namespace util
}  // namespace lely

#endif  // !LELY_UTIL_CORO_SCHED_HPP_
