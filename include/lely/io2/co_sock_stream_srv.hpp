/**@file
 * This header file is part of the I/O library; it contains the base class for
 * stream socket server accept operation with a stackless coroutine as the
 * completion task.
 *
 * @see lely/util/coroutine.hpp, lely/io2/sock_stream_srv.hpp
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

#ifndef LELY_IO2_CO_SOCK_STREAM_SRV_HPP_
#define LELY_IO2_CO_SOCK_STREAM_SRV_HPP_

#include <lely/io2/co_sock.hpp>
#include <lely/io2/sock_stream_srv.hpp>

namespace lely {
namespace io {

/**
 * A stream socket server accept operation with a stackless coroutine as the
 * completion task.
 */
class CoStreamSocketServerAccept : public io_sock_stream_srv_accept,
                                   public util::Coroutine {
 public:
  /// Constructs an accept operation.
  CoStreamSocketServerAccept(io_sock_stream_t* sock, io_endp* endp = nullptr,
                             ev_exec_t* exec = nullptr) noexcept
      : io_sock_stream_srv_accept IO_SOCK_STREAM_SRV_ACCEPT_INIT(
            sock, endp, exec, [](ev_task * task) noexcept {
              auto accept = io_sock_stream_srv_accept_from_task(task);
              ::std::error_code ec = util::make_error_code(accept->errc);
              auto self = static_cast<CoStreamSocketServerAccept*>(accept);
              (*self)(ec);
            }) {}

  virtual ~CoStreamSocketServerAccept() = default;

  operator ev_task&() & noexcept { return task; }

  /// Returns the executor to which the completion task is (to be) submitted.
  ev::Executor
  get_executor() const noexcept {
    return ev::Executor(task.exec);
  }

  /**
   * The coroutine to be executed once the accept operation completes (or is
   * canceled).
   *
   * @param ec the error code if an error occurred or the operation was
   *           canceled.
   */
  virtual void operator()(::std::error_code ec) noexcept = 0;
};

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_CO_SOCK_STREAM_SRV_HPP_
