/**@file
 * This header file is part of the I/O library; it contains the C++ interface
 * for the abstract socket.
 *
 * @see lely/io2/sock.h
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

#ifndef LELY_IO2_SOCK_HPP_
#define LELY_IO2_SOCK_HPP_

#include <lely/ev/future.hpp>
#include <lely/io2/dev.hpp>
#include <lely/io2/endp.hpp>
#include <lely/io2/event.hpp>
#include <lely/io2/sock.h>

#include <utility>

namespace lely {
namespace io {

/// The flags for socket send and receive operations.
enum class MessageFlag : int {
  /// Send without using routing tables.
  DONTROUTE = IO_MSG_DONTROUTE,
  /// Terminates a record (if supported by the protocol).
  EOR = IO_MSG_EOR,
  /// Out-of-band data.
  OOB = IO_MSG_OOB,
  /// Leave received data in queue.
  PEEK = IO_MSG_PEEK,
  /// Normal data truncated.
  TRUNC = IO_MSG_TRUNC,
  NONE = IO_MSG_NONE
};

constexpr MessageFlag
operator~(MessageFlag rhs) {
  return static_cast<MessageFlag>(~static_cast<int>(rhs));
}

constexpr MessageFlag operator&(MessageFlag lhs, MessageFlag rhs) {
  return static_cast<MessageFlag>(static_cast<int>(lhs) &
                                  static_cast<int>(rhs));
}

constexpr MessageFlag
operator^(MessageFlag lhs, MessageFlag rhs) {
  return static_cast<MessageFlag>(static_cast<int>(lhs) ^
                                  static_cast<int>(rhs));
}

constexpr MessageFlag
operator|(MessageFlag lhs, MessageFlag rhs) {
  return static_cast<MessageFlag>(static_cast<int>(lhs) |
                                  static_cast<int>(rhs));
}

inline MessageFlag&
operator&=(MessageFlag& lhs, MessageFlag rhs) {
  return lhs = lhs & rhs;
}

inline MessageFlag&
operator^=(MessageFlag& lhs, MessageFlag rhs) {
  return lhs = lhs ^ rhs;
}

inline MessageFlag&
operator|=(MessageFlag& lhs, MessageFlag rhs) {
  return lhs = lhs | rhs;
}

/// The type of socket shutdown.
enum class ShutdownType : int {
  /// Disables further receive operations.
  RD = IO_SHUT_RD,
  /// Disables further send operations.
  WR = IO_SHUT_WR,
  /// Disables further send and receive operations.
  RDWR = IO_SHUT_RDWR
};

namespace detail {

template <class F>
class SocketWaitWrapper : public io_sock_wait {
 public:
  SocketWaitWrapper(Event events, ev_exec_t* exec, F&& f)
      : io_sock_wait IO_SOCK_WAIT_INIT(
            static_cast<int>(events), exec,
            [](ev_task * task) noexcept {
              auto wait = io_sock_wait_from_task(task);
              auto events = static_cast<Event>(wait->events);
              ::std::error_code ec;
              if (wait->errc) ec = util::make_error_code(wait->errc);
              auto self = static_cast<SocketWaitWrapper*>(wait);
              compat::invoke(::std::move(self->func_), events, ec);
              delete self;
            }),
        func_(::std::forward<F>(f)) {}

  SocketWaitWrapper(const SocketWaitWrapper&) = delete;

  SocketWaitWrapper& operator=(const SocketWaitWrapper&) = delete;

  operator ev_task&() & noexcept { return task; }

 private:
  typename ::std::decay<F>::type func_;
};

}  // namespace detail

/**
 * Creates a socket I/O event wait operation with a completion task. The
 * operation deletes itself after it is completed, so it MUST NOT be deleted
 * once it is submitted to a socket.
 */
template <class F>
inline typename ::std::enable_if<
    compat::is_invocable<F, Event, ::std::error_code>::value,
    detail::SocketWaitWrapper<F>*>::type
make_socket_wait_wrapper(Event events, ev_exec_t* exec, F&& f) {
  return new detail::SocketWaitWrapper<F>(events, exec, ::std::forward<F>(f));
}

/**
 * An I/O event wait operation suitable for use with a socket. This class stores
 * a callable object with signature `void(Event events, std::error_code ec)`,
 * which is invoked upon completion (or cancellation) of the wait operation.
 */
class SocketWait : public io_sock_wait {
 public:
  using Signature = void(Event, ::std::error_code);

  /// Constructs a wait operation with a completion task.
  template <class F>
  SocketWait(Event events, ev_exec_t* exec, F&& f)
      : io_sock_wait
        IO_SOCK_WAIT_INIT(static_cast<int>(events), exec,
                          [](ev_task * task) noexcept {
                            auto wait = io_sock_wait_from_task(task);
                            auto self = static_cast<SocketWait*>(wait);
                            if (self->func_) {
                              auto events = static_cast<Event>(wait->events);
                              ::std::error_code ec;
                              if (wait->errc)
                                ec = util::make_error_code(wait->errc);
                              self->func_(events, ec);
                            }
                          }),
        func_(::std::forward<F>(f)) {}

  /// Constructs a wait operation with a completion task.
  template <class F>
  SocketWait(const Event events, F&& f)
      : SocketWait(events, nullptr, ::std::forward<F>(f)) {}

  SocketWait(const SocketWait&) = delete;

  SocketWait& operator=(const SocketWait&) = delete;

  operator ev_task&() & noexcept { return task; }

  /// Returns the executor to which the completion task is (to be) submitted.
  ev::Executor
  get_executor() const noexcept {
    return ev::Executor(task.exec);
  }

 private:
  ::std::function<Signature> func_;
};

/**
 * A reference to an abstract socket. This class is a wrapper around
 * `#io_sock_t*`.
 */
class SocketBase : public virtual Device {
 public:
  using Device::operator io_dev_t*;

  explicit SocketBase(io_sock_t* sock_) noexcept
      : Device(nullptr), sock(sock_) {}

  operator io_sock_t*() const noexcept { return sock; }

  /// @see io_sock_bind()
  void
  bind(const io_endp* endp, bool reuseaddr, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_sock_bind(*this, endp, reuseaddr))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_sock_bind()
  void
  bind(const io_endp* endp = nullptr, bool reuseaddr = false) {
    ::std::error_code ec;
    bind(endp, reuseaddr, ec);
    if (ec) throw ::std::system_error(ec, "bind");
  }

  /// @see io_sock_getsockname()
  void
  getsockname(io_endp* endp, ::std::error_code& ec) const noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_sock_getsockname(*this, endp))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_sock_getsockname()
  void
  getsockname(io_endp* endp = nullptr) const {
    ::std::error_code ec;
    getsockname(endp, ec);
    if (ec) throw ::std::system_error(ec, "getsockname");
  }

  /// @see io_sock_is_open()
  bool
  is_open() const noexcept {
    return io_sock_is_open(*this) != 0;
  }

  /// @see io_sock_close()
  void
  close(::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_sock_close(*this))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_sock_close()
  void
  close() {
    ::std::error_code ec;
    close(ec);
    if (ec) throw ::std::system_error(ec, "close");
  }

  /// @see io_sock_wait()
  void
  wait(Event& events, int timeout, ::std::error_code& ec) {
    int errsv = get_errc();
    set_errc(0);
    if (!io_sock_wait(*this, reinterpret_cast<int*>(&events), timeout))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_sock_wait()
  void
  wait(Event& events, int timeout = -1) {
    ::std::error_code ec;
    wait(events, timeout, ec);
    if (ec) throw ::std::system_error(ec, "wait");
  }

  /// @see io_sock_submit_wait()
  void
  submit_wait(struct io_sock_wait& wait) noexcept {
    io_sock_submit_wait(*this, &wait);
  }

  /// @see io_sock_submit_wait()
  template <class F>
  void
  submit_wait(Event events, ev_exec_t* exec, F&& f) {
    submit_wait(*make_socket_wait_wrapper(events, exec, ::std::forward<F>(f)));
  }

  /// @see io_sock_cancel_wait()
  bool
  cancel_wait(struct io_sock_wait& wait) noexcept {
    return io_sock_cancel_wait(*this, &wait) != 0;
  }

  /// @see io_sock_abort_wait()
  bool
  abort_wait(struct io_sock_wait& wait) noexcept {
    return io_sock_abort_wait(*this, &wait) != 0;
  }

  /// @see io_sock_async_wait()
  ev::Future<void, int>
  async_wait(ev_exec_t* exec, Event& events,
             struct io_sock_wait** pwait = nullptr) {
    auto future =
        io_sock_async_wait(*this, exec, reinterpret_cast<int*>(&events), pwait);
    if (!future) util::throw_errc("async_wait");
    return ev::Future<void, int>(future);
  }

  /// @see io_sock_async_wait()
  ev::Future<void, int>
  async_wait(Event& events, struct io_sock_wait** pwait = nullptr) {
    return async_wait(nullptr, events, pwait);
  }

  /// @see io_sock_get_error()
  ::std::error_code
  get_error() noexcept {
    return util::make_error_code(io_sock_get_error(*this));
  }

  /// @see io_sock_get_nread()
  int
  nread() const noexcept {
    return io_sock_get_nread(*this);
  }

  /// @see io_sock_get_dontroute()
  bool
  dontroute(::std::error_code& ec) const noexcept {
    int errsv = get_errc();
    set_errc(0);
    int optval = io_sock_get_dontroute(*this);
    if (optval >= 0)
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
    return optval > 0;
  }

  /// @see io_sock_get_dontroute()
  bool
  dontroute() const {
    ::std::error_code ec;
    auto optval = dontroute(ec);
    if (ec) throw ::std::system_error(ec, "dontroute");
    return optval;
  }

  /// @see io_sock_set_dontroute()
  void
  dontroute(bool optval, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_sock_set_dontroute(*this, optval))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_sock_set_dontroute()
  void
  dontroute(bool optval) {
    ::std::error_code ec;
    dontroute(optval, ec);
    if (ec) throw ::std::system_error(ec, "dontroute");
  }

  /// @see io_sock_get_rcvbuf()
  int
  receive_buffer_size(::std::error_code& ec) const noexcept {
    int errsv = get_errc();
    set_errc(0);
    int optval = io_sock_get_rcvbuf(*this);
    if (optval >= 0)
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
    return optval;
  }

  /// @see io_sock_get_rcvbuf()
  int
  receive_buffer_size() const {
    ::std::error_code ec;
    auto optval = receive_buffer_size(ec);
    if (ec) throw ::std::system_error(ec, "receive_buffer_size");
    return optval;
  }

  /// @see io_sock_set_rcvbuf()
  void
  receive_buffer_size(int optval, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_sock_set_rcvbuf(*this, optval))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_sock_set_rcvbuf()
  void
  receive_buffer_size(int optval) {
    ::std::error_code ec;
    receive_buffer_size(optval, ec);
    if (ec) throw ::std::system_error(ec, "receive_buffer_size");
  }

  /// @see io_sock_get_sndbuf()
  int
  send_buffer_size(::std::error_code& ec) const noexcept {
    int errsv = get_errc();
    set_errc(0);
    int optval = io_sock_get_sndbuf(*this);
    if (optval >= 0)
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
    return optval;
  }

  /// @see io_sock_get_sndbuf()
  int
  send_buffer_size() const {
    ::std::error_code ec;
    auto optval = send_buffer_size(ec);
    if (ec) throw ::std::system_error(ec, "send_buffer_size");
    return optval;
  }

  /// @see io_sock_set_sndbuf()
  void
  send_buffer_size(int optval, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_sock_set_sndbuf(*this, optval))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_sock_set_sndbuf()
  void
  send_buffer_size(int optval) {
    ::std::error_code ec;
    send_buffer_size(optval, ec);
    if (ec) throw ::std::system_error(ec, "send_buffer_size");
  }

 protected:
  io_sock_t* sock{nullptr};
};

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_SOCK_HPP_
