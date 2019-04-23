/**@file
 * This header file is part of the I/O library; it contains the C++ interface
 * for the abstract stream socket server.
 *
 * @see lely/io2/sock_stream_srv.h
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

#ifndef LELY_IO2_SOCK_STREAM_SRV_HPP_
#define LELY_IO2_SOCK_STREAM_SRV_HPP_

#include <lely/io2/sock_stream.hpp>
#include <lely/io2/sock_stream_srv.h>

#include <utility>

namespace lely {
namespace io {

namespace detail {

template <class F>
class StreamSocketServerAcceptWrapper : public io_sock_stream_srv_accept {
 public:
  StreamSocketServerAcceptWrapper(io_sock_stream_t* sock, io_endp* endp,
                                  ev_exec_t* exec, F&& f)
      : io_sock_stream_srv_accept IO_SOCK_STREAM_SRV_ACCEPT_INIT(
            sock, endp, exec,
            [](ev_task* task) {
              auto accept = io_sock_stream_srv_accept_from_task(task);
              ::std::error_code ec = util::make_error_code(accept->errc);
              auto self = static_cast<StreamSocketServerAcceptWrapper*>(accept);
              compat::invoke(::std::move(self->func_), ec);
              delete self;
            }),
        func_(::std::forward<F>(f)) {}

  StreamSocketServerAcceptWrapper(const StreamSocketServerAcceptWrapper&) =
      delete;

  StreamSocketServerAcceptWrapper& operator=(
      const StreamSocketServerAcceptWrapper&) = delete;

  operator ev_task&() & noexcept { return task; }

 private:
  typename ::std::decay<F>::type func_;
};

}  // namespace detail

/**
 * Creates a stream socket server accept operation with a completion task. The
 * operation deletes itself after it is completed, so it MUST NOT be deleted
 * once it is submitted to a server.
 */
template <class F>
// clang-format off
inline typename ::std::enable_if<
    compat::is_invocable<F, ::std::error_code>::value,
    detail::StreamSocketServerAcceptWrapper<F>*>::type
make_stream_socket_server_accept_wrapper(io_sock_stream_t* sock, io_endp* endp,
                                         ev_exec_t* exec, F&& f) {
  // clang-format on
  return new detail::StreamSocketServerAcceptWrapper<F>(sock, endp, exec,
                                                        ::std::forward<F>(f));
}

/**
 * An accept operation suitable for use with a stream socket server. This class
 * stores a callable object with signature `void(std::error_code ec)`, which is
 * invoked upon completion (or cancellation) of the accept operation.
 */
class StreamSocketServerAccept : public io_sock_stream_srv_accept {
 public:
  using Signature = void(::std::error_code);

  /// Constructs a accept operation with a completion task.
  template <class F>
  StreamSocketServerAccept(io_sock_stream_t* sock, io_endp* endp,
                           ev_exec_t* exec, F&& f)
      : io_sock_stream_srv_accept IO_SOCK_STREAM_SRV_ACCEPT_INIT(
            sock, endp, exec,
            [](ev_task* task) {
              auto accept = io_sock_stream_srv_accept_from_task(task);
              auto self = static_cast<StreamSocketServerAccept*>(accept);
              if (self->func_) {
                ::std::error_code ec = util::make_error_code(accept->errc);
                self->func_(ec);
              }
            }),
        func_(::std::forward<F>(f)) {}

  /// Constructs a accept operation with a completion task.
  template <class F>
  StreamSocketServerAccept(io_sock_stream_t* sock, ev_exec_t* exec, F&& f)
      : StreamSocketServerAccept(sock, nullptr, exec, ::std::forward<F>(f)) {}

  /// Constructs a accept operation with a completion task.
  template <class F>
  StreamSocketServerAccept(io_sock_stream_t* sock, io_endp* endp, F&& f)
      : StreamSocketServerAccept(sock, endp, nullptr, ::std::forward<F>(f)) {}

  /// Constructs a accept operation with a completion task.
  template <class F>
  StreamSocketServerAccept(io_sock_stream_t* sock, F&& f)
      : StreamSocketServerAccept(sock, nullptr, nullptr, ::std::forward<F>(f)) {
  }

  StreamSocketServerAccept(const StreamSocketServerAccept&) = delete;

  StreamSocketServerAccept& operator=(const StreamSocketServerAccept&) = delete;

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
 * A reference to a stream socket server. This class is a wrapper around
 * `#io_sock_stream_srv_t*`.
 */
class StreamSocketServerBase : public SocketBase {
 public:
  using SocketBase::operator io_sock_t*;

  explicit StreamSocketServerBase(
      io_sock_stream_srv_t* sock_stream_srv_) noexcept
      : Device(sock_stream_srv_ ? io_sock_stream_srv_get_dev(sock_stream_srv_)
                                : nullptr),
        SocketBase(sock_stream_srv_
                       ? io_sock_stream_srv_get_sock(sock_stream_srv_)
                       : nullptr),
        sock_stream_srv(sock_stream_srv_) {}

  operator io_sock_stream_srv_t*() const noexcept { return sock_stream_srv; }

  /// @see io_sock_stream_srv_listen()
  void
  listen(int backlog, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_sock_stream_srv_listen(*this, backlog))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_sock_stream_srv_get_maxconn()
  int
  get_maxconn() const noexcept {
    return io_sock_stream_srv_get_maxconn(*this);
  }

  /// @see io_sock_stream_srv_listen()
  void
  listen(int backlog = 0) {
    ::std::error_code ec;
    listen(backlog, ec);
    if (ec) throw ::std::system_error(ec, "listen");
  }

  /// @see io_sock_stream_srv_is_listening()
  int
  is_listening(::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    int result = io_sock_stream_srv_is_listening(*this);
    if (result >= 0)
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
    return result;
  }

  /// @see io_sock_stream_srv_is_listening()
  bool
  is_listening() {
    ::std::error_code ec;
    int result = is_listening(ec);
    if (result < 0) throw ::std::system_error(ec, "is_listening");
    return result != 0;
  }

  /// @see io_sock_stream_srv_accept()
  void
  accept(io_sock_stream_t* sock, io_endp* endp, int timeout,
         ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_sock_stream_srv_accept(*this, sock, endp, timeout))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_sock_stream_srv_accept()
  void
  accept(io_sock_stream_t* sock, int timeout, ::std::error_code& ec) noexcept {
    accept(sock, nullptr, timeout, ec);
  }

  /// @see io_sock_stream_srv_accept()
  void
  accept(io_sock_stream_t* sock, io_endp* endp = nullptr, int timeout = -1) {
    ::std::error_code ec;
    accept(sock, endp, timeout, ec);
    if (ec) throw ::std::system_error(ec, "accept");
  }

  /// @see io_sock_stream_srv_submit_accept()
  void
  submit_accept(struct io_sock_stream_srv_accept& accept) noexcept {
    io_sock_stream_srv_submit_accept(*this, &accept);
  }

  /// @see io_sock_stream_srv_submit_accept()
  template <class F>
  void
  submit_accept(io_sock_stream_t* sock, io_endp* endp, ev_exec_t* exec, F&& f) {
    submit_accept(*make_stream_socket_server_accept_wrapper(
        sock, endp, exec, ::std::forward<F>(f)));
  }

  /// @see io_sock_stream_srv_submit_accept()
  template <class F>
  void
  submit_accept(io_sock_stream_t* sock, ev_exec_t* exec, F&& f) {
    submit_accept(sock, nullptr, nullptr, exec, ::std::forward<F>(f));
  }

  /// @see io_sock_stream_srv_submit_accept()
  template <class F>
  void
  submit_accept(io_sock_stream_t* sock, io_endp* endp, F&& f) {
    submit_accept(sock, endp, nullptr, ::std::forward<F>(f));
  }

  /// @see io_sock_stream_srv_submit_accept()
  template <class F>
  void
  submit_accept(io_sock_stream_t* sock, F&& f) {
    submit_accept(sock, nullptr, nullptr, ::std::forward<F>(f));
  }

  /// @see io_sock_stream_srv_cancel_accept()
  bool
  cancel_accept(struct io_sock_stream_srv_accept& accept) noexcept {
    return io_sock_stream_srv_cancel_accept(*this, &accept) != 0;
  }

  /// @see io_sock_stream_srv_abort_accept()
  bool
  abort_accept(struct io_sock_stream_srv_accept& accept) noexcept {
    return io_sock_stream_srv_abort_accept(*this, &accept) != 0;
  }

  /// @see io_sock_stream_srv_async_accept()
  ev::Future<void, int>
  async_accept(ev_exec_t* exec, io_sock_stream_t* sock, io_endp* endp = nullptr,
               struct io_sock_stream_srv_accept** paccept = nullptr) {
    auto future =
        io_sock_stream_srv_async_accept(*this, exec, sock, endp, paccept);
    if (!future) util::throw_errc("async_accept");
    return ev::Future<void, int>(future);
  }

  /// @see io_sock_stream_srv_async_accept()
  ev::Future<void, int>
  async_accept(io_sock_stream_t* sock, io_endp* endp = nullptr,
               struct io_sock_stream_srv_accept** paccept = nullptr) {
    return async_accept(nullptr, sock, endp, paccept);
  }

 protected:
  io_sock_stream_srv_t* sock_stream_srv{nullptr};
};

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_SOCK_STREAM_SRV_HPP_
