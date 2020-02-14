/**@file
 * This header file is part of the event library; it contains the C++ interface
 * for the file descriptor event loop.
 *
 * @see lely/io2/posix/fd_loop.h
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

#ifndef LELY_IO2_POSIX_FD_LOOP_HPP_
#define LELY_IO2_POSIX_FD_LOOP_HPP_

#include <lely/ev/exec.hpp>
#include <lely/ev/poll.hpp>
#include <lely/io2/posix/fd_loop.h>

#include <utility>

namespace lely {
namespace io {

/// A file descriptor event loop.
class FdLoop {
 public:
  /// @see io_fd_loop_create()
  FdLoop(io_poll_t* poll) : loop_(io_fd_loop_create(poll)) {
    if (!loop_) util::throw_errc("FdLoop");
  }

  FdLoop(const FdLoop&) = delete;

  FdLoop(FdLoop&& other) noexcept : loop_(other.loop_) {
    other.loop_ = nullptr;
  }

  FdLoop& operator=(const FdLoop&) = delete;

  FdLoop&
  operator=(FdLoop&& other) noexcept {
    using ::std::swap;
    swap(loop_, other.loop_);
    return *this;
  }

  /// @see io_fd_loop_destroy()
  ~FdLoop() { io_fd_loop_destroy(*this); }

  operator io_fd_loop_t*() const noexcept { return loop_; }

  /// @see io_fd_loop_get_poll()
  ev::Poll
  get_poll() const noexcept {
    return ev::Poll(io_fd_loop_get_poll(*this));
  }

  /// @see io_fd_loop_get_exec()
  ev::Executor
  get_executor() const noexcept {
    return ev::Executor(io_fd_loop_get_exec(*this));
  }

  /// @see io_fd_loop_get_fd()
  int
  get_fd() const noexcept {
    return io_fd_loop_get_fd(*this);
  }

  /// @see io_fd_loop_stop()
  void
  stop() noexcept {
    io_fd_loop_stop(*this);
  }

  ///@ see io_fd_loop_stopped()
  bool
  stopped() const noexcept {
    return io_fd_loop_stopped(*this) != 0;
  }

  /// @see io_fd_loop_stop()
  void
  restart() noexcept {
    io_fd_loop_restart(*this);
  }

  /// @see io_fd_loop_run()
  ::std::size_t
  run() {
    ::std::error_code ec;
    auto result = run(ec);
    if (ec) throw ::std::system_error(ec, "run");
    return result;
  }

  /// @see io_fd_loop_run()
  ::std::size_t
  run(::std::error_code& ec) {
    int errsv = get_errc();
    set_errc(0);
    auto result = io_fd_loop_run(*this);
    ec = util::make_error_code();
    set_errc(errsv);
    return result;
  }

  /// @see io_fd_loop_run_one()
  ::std::size_t
  run_one() {
    ::std::error_code ec;
    auto result = run_one(ec);
    if (ec) throw ::std::system_error(ec, "run_one");
    return result;
  }

  /// @see io_fd_loop_run_one()
  ::std::size_t
  run_one(::std::error_code& ec) {
    int errsv = get_errc();
    set_errc(0);
    auto result = io_fd_loop_run_one(*this);
    ec = util::make_error_code();
    set_errc(errsv);
    return result;
  }

 private:
  io_fd_loop_t* loop_{nullptr};
};

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_POSIX_FD_LOOP_HPP_
