/**@file
 * This header file is part of the I/O library; it contains the base class for
 * socket I/O event wait operation with a stackless coroutine as the completion
 * task.
 *
 * @see lely/util/coroutine.hpp, lely/io2/sock.hpp
 *
 * @copyright 2019 Lely Industries N.V.
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

#ifndef LELY_IO2_CO_SOCK_HPP_
#define LELY_IO2_CO_SOCK_HPP_

#include <lely/io2/sock.hpp>
#include <lely/util/coroutine.hpp>

namespace lely {
namespace io {

/**
 * A socket I/O event wait operation with a stackless coroutine as the
 * completion task.
 */
class CoSocketWait : public io_sock_wait, public util::Coroutine {
 public:
  /// Constructs a wait operation.
  CoSocketWait(Event events, ev_exec_t* exec = nullptr) noexcept
      : io_sock_wait IO_SOCK_WAIT_INIT(
            static_cast<int>(events), exec, [](ev_task * task) noexcept {
              auto wait = io_sock_wait_from_task(task);
              auto events = static_cast<Event>(wait->events);
              ::std::error_code ec;
              if (wait->errc) ec = util::make_error_code(wait->errc);
              auto self = static_cast<CoSocketWait*>(wait);
              (*self)(events, ec);
            }) {}

  virtual ~CoSocketWait() = default;

  operator ev_task&() & noexcept { return task; }

  /// Returns the executor to which the completion task is (to be) submitted.
  ev::Executor
  get_executor() const noexcept {
    return ev::Executor(task.exec);
  }

  /**
   * The coroutine to be executed once the wait operation completes (or is
   * canceled).
   *
   * @param events the reported I/O events.
   * @param ec     the error code if an error occurred or the operation was
   *               canceled.
   */
  virtual void operator()(Event events, ::std::error_code ec) noexcept = 0;
};

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_CO_SOCK_HPP_
