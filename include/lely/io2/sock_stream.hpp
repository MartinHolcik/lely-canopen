/**@file
 * This header file is part of the I/O library; it contains the C++ interface
 * for the abstract stream socket.
 *
 * @see lely/io2/sock_stream.h
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

#ifndef LELY_IO2_SOCK_STREAM_HPP_
#define LELY_IO2_SOCK_STREAM_HPP_

#include <lely/io2/sock.hpp>
#include <lely/io2/sock_stream.h>
#include <lely/io2/stream.hpp>

#include <utility>

namespace lely {
namespace io {

namespace detail {

template <class F>
class StreamSocketConnectWrapper : public io_sock_stream_connect {
 public:
  StreamSocketConnectWrapper(const io_endp* endp, ev_exec_t* exec, F&& f)
      : io_sock_stream_connect IO_SOCK_STREAM_CONNECT_INIT(
            endp, exec,
            [](ev_task* task) {
              auto connect = io_sock_stream_connect_from_task(task);
              ::std::error_code ec = util::make_error_code(connect->errc);
              auto self = static_cast<StreamSocketConnectWrapper*>(connect);
              compat::invoke(::std::move(self->func_), ec);
              delete self;
            }),
        func_(::std::forward<F>(f)) {}

  StreamSocketConnectWrapper(const StreamSocketConnectWrapper&) = delete;

  StreamSocketConnectWrapper& operator=(const StreamSocketConnectWrapper&) =
      delete;

  operator ev_task&() & noexcept { return task; }

 private:
  typename ::std::decay<F>::type func_;
};

}  // namespace detail

/**
 * Creates a stream socket connect operation with a completion task. The
 * operation deletes itself after it is completed, so it MUST NOT be deleted
 * once it is submitted to a stream socket.
 */
template <class F>
// clang-format off
inline typename ::std::enable_if<
    compat::is_invocable<F, ::std::error_code>::value,
    detail::StreamSocketConnectWrapper<F>*>::type
make_stream_socket_connect_wrapper(const io_endp* endp, ev_exec_t* exec,
                                   F&& f) {
  // clang-format on
  return new detail::StreamSocketConnectWrapper<F>(endp, exec,
                                                   ::std::forward<F>(f));
}

/**
 * A connect operation suitable for use with a stream socket. This class stores
 * a callable object with signature `void(std::error_code ec)`, which is invoked
 * upon completion (or cancellation) of the connect operation.
 */
class StreamSocketConnect : public io_sock_stream_connect {
 public:
  using Signature = void(::std::error_code);

  /// Constructs a connect operation with a completion task.
  template <class F>
  StreamSocketConnect(const io_endp* endp, ev_exec_t* exec, F&& f)
      : io_sock_stream_connect IO_SOCK_STREAM_CONNECT_INIT(
            endp, exec,
            [](ev_task* task) {
              auto connect = io_sock_stream_connect_from_task(task);
              auto self = static_cast<StreamSocketConnect*>(connect);
              if (self->func_) {
                ::std::error_code ec = util::make_error_code(connect->errc);
                self->func_(ec);
              }
            }),
        func_(::std::forward<F>(f)) {}

  /// Constructs a connect operation with a completion task.
  template <class F>
  StreamSocketConnect(const io_endp* endp, F&& f)
      : StreamSocketConnect(endp, nullptr, ::std::forward<F>(f)) {}

  StreamSocketConnect(const StreamSocketConnect&) = delete;

  StreamSocketConnect& operator=(const StreamSocketConnect&) = delete;

  operator ev_task&() & noexcept { return task; }

  /// Returns the executor to which the completion task is (to be) submitted.
  ev::Executor
  get_executor() const noexcept {
    return ev::Executor(task.exec);
  }

 private:
  ::std::function<Signature> func_;
};

namespace detail {

template <class F>
class StreamSocketReceiveSequenceWrapper : public io_sock_stream_recvmsg {
 public:
  template <class BufferSequence>
  StreamSocketReceiveSequenceWrapper(BufferSequence& buffers, MessageFlag flags,
                                     ev_exec_t* exec, F&& f)
      : io_sock_stream_recvmsg IO_SOCK_STREAM_RECVMSG_INIT(
            nullptr, 0, static_cast<int>(flags), exec,
            [](struct ev_task * task) noexcept {
              auto recvmsg = io_sock_stream_recvmsg_from_task(task);
              auto result = recvmsg->r.result;
              auto flags = static_cast<MessageFlag>(recvmsg->flags);
              ::std::error_code ec;
              if (result == -1) ec = util::make_error_code(recvmsg->r.errc);
              auto self =
                  static_cast<StreamSocketReceiveSequenceWrapper*>(recvmsg);
              compat::invoke(::std::move(self->func_), result, flags, ec);
              delete self;
            }),
        buf_(buffers),
        func_(::std::forward<F>(f)) {
    buf = buf_.buf();
    bufcnt = buf_.bufcnt();
  }

  StreamSocketReceiveSequenceWrapper(
      const StreamSocketReceiveSequenceWrapper&) = delete;

  StreamSocketReceiveSequenceWrapper& operator=(
      const StreamSocketReceiveSequenceWrapper&) = delete;

  operator ev_task&() & noexcept { return task; }

 private:
  detail::BufferArray buf_;
  typename ::std::decay<F>::type func_;
};

}  // namespace detail

/**
 * Creates a vectored stream socket receive operation with a completion task.
 * The operation deletes itself after it is completed, so it MUST NOT be deleted
 * once it is submitted to a stream socket.
 */
template <class BufferSequence, class F>
inline typename ::std::enable_if<
    compat::is_invocable<F, ssize_t, MessageFlag, ::std::error_code>::value,
    detail::StreamSocketReceiveSequenceWrapper<F>*>::type
make_stream_socket_receive_sequence_wrapper(BufferSequence& buffers,
                                            MessageFlag flags, ev_exec_t* exec,
                                            F&& f) {
  return new detail::StreamSocketReceiveSequenceWrapper<F>(
      buffers, flags, exec, ::std::forward<F>(f));
}

/**
 * A vectored receive operation suitable for use with a stream socket. This
 * class stores a callable object with signature
 * `void(ssize_t result, MessageFlag flags, std::error_code ec)`, which is
 * invoked upon completion (or cancellation) of the receive operation.
 */
class StreamSocketReceiveSequence : public io_sock_stream_recvmsg {
 public:
  using Signature = void(ssize_t, MessageFlag, ::std::error_code);

  /// Constructs a vectored receive operation with a completion task.
  template <class BufferSequence, class F>
  StreamSocketReceiveSequence(BufferSequence& buffers, MessageFlag flags,
                              ev_exec_t* exec, F&& f)
      : io_sock_stream_recvmsg IO_SOCK_STREAM_RECVMSG_INIT(
            nullptr, 0, static_cast<int>(flags), exec,
            [](struct ev_task * task) noexcept {
              auto recvmsg = io_sock_stream_recvmsg_from_task(task);
              auto self = static_cast<StreamSocketReceiveSequence*>(recvmsg);
              if (self->func_) {
                auto result = recvmsg->r.result;
                auto flags = static_cast<MessageFlag>(recvmsg->flags);
                ::std::error_code ec;
                if (result == -1) ec = util::make_error_code(recvmsg->r.errc);
                self->func_(result, flags, ec);
              }
            }),
        buf_(buffers),
        func_(::std::forward<F>(f)) {
    buf = buf_.buf();
    bufcnt = buf_.bufcnt();
  }

  /// Constructs a vectored receive operation with a completion task.
  template <class BufferSequence, class F>
  StreamSocketReceiveSequence(BufferSequence& buffers, MessageFlag flags, F&& f)
      : StreamSocketReceiveSequence(buffers, flags, nullptr,
                                    ::std::forward<F>(f)) {}

  StreamSocketReceiveSequence(const StreamSocketReceiveSequence&) = delete;

  StreamSocketReceiveSequence& operator=(const StreamSocketReceiveSequence&) =
      delete;

  operator ev_task&() & noexcept { return task; }

  /// Returns the executor to which the completion task is (to be) submitted.
  ev::Executor
  get_executor() const noexcept {
    return ev::Executor(task.exec);
  }

 private:
  detail::BufferArray buf_;
  ::std::function<Signature> func_;
};

namespace detail {

template <class F>
class StreamSocketReceiveWrapper : public io_sock_stream_recv {
 public:
  StreamSocketReceiveWrapper(const Buffer& buffer, MessageFlag flags,
                             ev_exec_t* exec, F&& f)
      : io_sock_stream_recv IO_SOCK_STREAM_RECV_INIT(
            this, buffer.data(), buffer.size(), static_cast<int>(flags), exec,
            [](ev_task * task) noexcept {
              auto recv = io_sock_stream_recv_from_task(task);
              auto result = recv->recvmsg.r.result;
              auto flags = static_cast<MessageFlag>(recv->recvmsg.flags);
              ::std::error_code ec;
              if (result == -1)
                ec = util::make_error_code(recv->recvmsg.r.errc);
              auto self = static_cast<StreamSocketReceiveWrapper*>(recv);
              compat::invoke(::std::move(self->func_), result, flags, ec);
              delete self;
            }),
        func_(::std::forward<F>(f)) {}

  StreamSocketReceiveWrapper(const StreamSocketReceiveWrapper&) = delete;

  StreamSocketReceiveWrapper& operator=(const StreamSocketReceiveWrapper&) =
      delete;

  operator ev_task&() & noexcept { return recvmsg.task; }

 private:
  typename ::std::decay<F>::type func_;
};

}  // namespace detail

/**
 * Creates a stream socket receive operation with a completion task. The
 * operation deletes itself after it is completed, so it MUST NOT be deleted
 * once it is submitted to a stream socket.
 */
template <class F>
inline typename ::std::enable_if<
    compat::is_invocable<F, ssize_t, MessageFlag, ::std::error_code>::value,
    detail::StreamSocketReceiveWrapper<F>*>::type
make_stream_socket_receive_wrapper(const Buffer& buffer, MessageFlag flags,
                                   ev_exec_t* exec, F&& f) {
  return new detail::StreamSocketReceiveWrapper<F>(buffer, flags, exec,
                                                   ::std::forward<F>(f));
}

/**
 * A receive operation suitable for use with a stream socket. This class stores
 * a callable object with signature
 * `void(ssize_t result, MessageFlag flags, std::error_code ec)`, which is
 * invoked upon completion (or cancellation) of the receive operation.
 */
class StreamSocketReceive : public io_sock_stream_recv {
 public:
  using Signature = void(ssize_t, MessageFlag, ::std::error_code);

  /// Constructs a receive operation with a completion task.
  template <class F>
  StreamSocketReceive(const Buffer& buffer, MessageFlag flags, ev_exec_t* exec,
                      F&& f)
      : io_sock_stream_recv IO_SOCK_STREAM_RECV_INIT(
            this, buffer.data(), buffer.size(), static_cast<int>(flags), exec,
            [](ev_task * task) noexcept {
              auto recv = io_sock_stream_recv_from_task(task);
              auto self = static_cast<StreamSocketReceive*>(recv);
              if (self->func_) {
                auto result = recv->recvmsg.r.result;
                auto flags = static_cast<MessageFlag>(recv->recvmsg.flags);
                ::std::error_code ec;
                if (result == -1)
                  ec = util::make_error_code(recv->recvmsg.r.errc);
                self->func_(result, flags, ec);
              }
            }),
        func_(::std::forward<F>(f)) {}

  /// Constructs a receive operation with a completion task.
  template <class F>
  StreamSocketReceive(const Buffer& buffer, MessageFlag flags, F&& f)
      : StreamSocketReceive(buffer, flags, nullptr, ::std::forward<F>(f)) {}

  StreamSocketReceive(const StreamSocketReceive&) = delete;

  StreamSocketReceive& operator=(const StreamSocketReceive&) = delete;

  operator ev_task&() & noexcept { return recvmsg.task; }

  /// Returns the executor to which the completion task is (to be) submitted.
  ev::Executor
  get_executor() const noexcept {
    return ev::Executor(recvmsg.task.exec);
  }

 private:
  ::std::function<Signature> func_;
};

namespace detail {

template <class F>
class StreamSocketSendSequenceWrapper : public io_sock_stream_sendmsg {
 public:
  template <class ConstBufferSequence>
  StreamSocketSendSequenceWrapper(const ConstBufferSequence& buffers,
                                  MessageFlag flags, ev_exec_t* exec, F&& f)
      : io_sock_stream_sendmsg IO_SOCK_STREAM_SENDMSG_INIT(
            nullptr, 0, static_cast<int>(flags), exec,
            [](struct ev_task * task) noexcept {
              auto sendmsg = io_sock_stream_sendmsg_from_task(task);
              auto result = sendmsg->r.result;
              ::std::error_code ec;
              if (result == -1) ec = util::make_error_code(sendmsg->r.errc);
              auto self =
                  static_cast<StreamSocketSendSequenceWrapper*>(sendmsg);
              compat::invoke(::std::move(self->func_), result, ec);
              delete self;
            }),
        buf_(buffers),
        func_(::std::forward<F>(f)) {
    buf = buf_.buf();
    bufcnt = buf_.bufcnt();
  }

  StreamSocketSendSequenceWrapper(const StreamSocketSendSequenceWrapper&) =
      delete;

  StreamSocketSendSequenceWrapper& operator=(
      const StreamSocketSendSequenceWrapper&) = delete;

  operator ev_task&() & noexcept { return task; }

 private:
  detail::ConstBufferArray buf_;
  typename ::std::decay<F>::type func_;
};

}  // namespace detail

/**
 * Creates a vectored stream socket send operation with a completion task. The
 * operation deletes itself after it is completed, so it MUST NOT be deleted
 * once it is submitted to a stream socket.
 */
template <class ConstBufferSequence, class F>
inline typename ::std::enable_if<
    compat::is_invocable<F, ssize_t, ::std::error_code>::value,
    detail::StreamSocketSendSequenceWrapper<F>*>::type
make_stream_socket_send_sequence_wrapper(const ConstBufferSequence& buffers,
                                         MessageFlag flags, ev_exec_t* exec,
                                         F&& f) {
  return new detail::StreamSocketSendSequenceWrapper<F>(buffers, flags, exec,
                                                        ::std::forward<F>(f));
}

/**
 * A vectored send operation suitable for use with a stream socket. This class
 * stores a callable object with signature
 * `void(ssize_t result, std::error_code ec)`, which is invoked upon completion
 * (or cancellation) of the send operation.
 */
class StreamSocketSendSequence : public io_sock_stream_sendmsg {
 public:
  using Signature = void(ssize_t, ::std::error_code);

  /// Constructs a vectored send operation with a completion task.
  template <class ConstBufferSequence, class F>
  StreamSocketSendSequence(const ConstBufferSequence& buffers,
                           MessageFlag flags, ev_exec_t* exec, F&& f)
      : io_sock_stream_sendmsg IO_SOCK_STREAM_SENDMSG_INIT(
            nullptr, 0, static_cast<int>(flags), exec,
            [](struct ev_task * task) noexcept {
              auto sendmsg = io_sock_stream_sendmsg_from_task(task);
              auto self = static_cast<StreamSocketSendSequence*>(sendmsg);
              if (self->func_) {
                auto result = sendmsg->r.result;
                ::std::error_code ec;
                if (result == -1) ec = util::make_error_code(sendmsg->r.errc);
                self->func_(result, ec);
              }
            }),
        buf_(buffers),
        func_(::std::forward<F>(f)) {
    buf = buf_.buf();
    bufcnt = buf_.bufcnt();
  }

  /// Constructs a vectored send operation with a completion task.
  template <class ConstBufferSequence, class F>
  StreamSocketSendSequence(const ConstBufferSequence& buffers,
                           MessageFlag flags, F&& f)
      : StreamSocketSendSequence(buffers, flags, nullptr,
                                 ::std::forward<F>(f)) {}

  StreamSocketSendSequence(const StreamSocketSendSequence&) = delete;

  StreamSocketSendSequence& operator=(const StreamSocketSendSequence&) = delete;

  operator ev_task&() & noexcept { return task; }

  /// Returns the executor to which the completion task is (to be) submitted.
  ev::Executor
  get_executor() const noexcept {
    return ev::Executor(task.exec);
  }

 private:
  detail::ConstBufferArray buf_;
  ::std::function<Signature> func_;
};

namespace detail {

template <class F>
class StreamSocketSendWrapper : public io_sock_stream_send {
 public:
  template <class ConstBuffer>
  StreamSocketSendWrapper(const ConstBuffer& buffer, MessageFlag flags,
                          ev_exec_t* exec, F&& f)
      : io_sock_stream_send IO_SOCK_STREAM_SEND_INIT(
            this, buffer.data(), buffer.size(), static_cast<int>(flags), exec,
            [](ev_task * task) noexcept {
              auto send = io_sock_stream_send_from_task(task);
              auto result = send->sendmsg.r.result;
              ::std::error_code ec;
              if (result == -1)
                ec = util::make_error_code(send->sendmsg.r.errc);
              auto self = static_cast<StreamSocketSendWrapper*>(send);
              compat::invoke(::std::move(self->func_), result, ec);
              delete self;
            }),
        func_(::std::forward<F>(f)) {}

  StreamSocketSendWrapper(const StreamSocketSendWrapper&) = delete;

  StreamSocketSendWrapper& operator=(const StreamSocketSendWrapper&) = delete;

  operator ev_task&() & noexcept { return sendmsg.task; }

 private:
  typename ::std::decay<F>::type func_;
};

}  // namespace detail

/**
 * Creates a stream socket send operation with a completion task. The operation
 * deletes itself after it is completed, so it MUST NOT be deleted once it is
 * submitted to a stream socket.
 */
template <class F>
inline typename ::std::enable_if<
    compat::is_invocable<F, ssize_t, ::std::error_code>::value,
    detail::StreamSocketSendWrapper<F>*>::type
make_stream_socket_send_wrapper(const ConstBuffer& buffer, MessageFlag flags,
                                ev_exec_t* exec, F&& f) {
  return new detail::StreamSocketSendWrapper<F>(buffer, flags, exec,
                                                ::std::forward<F>(f));
}

/**
 * A send operation suitable for use with a stream socket. This class stores a
 * callable object with signature `void(ssize_t result, std::error_code ec)`,
 * which is invoked upon completion (or cancellation) of the send operation.
 */
class StreamSocketSend : public io_sock_stream_send {
 public:
  using Signature = void(ssize_t, ::std::error_code);

  /// Constructs a send operation with a completion task.
  template <class F>
  StreamSocketSend(const ConstBuffer& buffer, MessageFlag flags,
                   ev_exec_t* exec, F&& f)
      : io_sock_stream_send IO_SOCK_STREAM_SEND_INIT(
            this, buffer.data(), buffer.size(), static_cast<int>(flags), exec,
            [](ev_task * task) noexcept {
              auto send = io_sock_stream_send_from_task(task);
              auto self = static_cast<StreamSocketSend*>(send);
              if (self->func_) {
                auto result = send->sendmsg.r.result;
                ::std::error_code ec;
                if (result == -1)
                  ec = util::make_error_code(send->sendmsg.r.errc);
                self->func_(result, ec);
              }
            }),
        func_(::std::forward<F>(f)) {}

  /// Constructs a send operation with a completion task.
  template <class F>
  StreamSocketSend(const ConstBuffer& buffer, MessageFlag flags, F&& f)
      : StreamSocketSend(buffer, flags, nullptr, ::std::forward<F>(f)) {}

  StreamSocketSend(const StreamSocketSend&) = delete;

  StreamSocketSend& operator=(const StreamSocketSend&) = delete;

  operator ev_task&() & noexcept { return sendmsg.task; }

  /// Returns the executor to which the completion task is (to be) submitted.
  ev::Executor
  get_executor() const noexcept {
    return ev::Executor(sendmsg.task.exec);
  }

 private:
  ::std::function<Signature> func_;
};

/**
 * A reference to a stream socket. This class is a wrapper around
 * `#io_sock_stream_t*`.
 */
class StreamSocketBase : public SocketBase, public StreamBase {
 public:
  using Device::operator io_dev_t*;
  using SocketBase::operator io_sock_t*;
  using StreamBase::operator io_stream_t*;

  explicit StreamSocketBase(io_sock_stream_t* sock_stream_) noexcept
      : Device(sock_stream_ ? io_sock_stream_get_dev(sock_stream_) : nullptr),
        SocketBase(sock_stream_ ? io_sock_stream_get_sock(sock_stream_)
                                : nullptr),
        StreamBase(sock_stream_ ? io_sock_stream_get_stream(sock_stream_)
                                : nullptr),
        sock_stream(sock_stream_) {}

  operator io_sock_stream_t*() const noexcept { return sock_stream; }

  /// @see io_sock_stream_connect()
  void
  connect(const io_endp* endp, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_sock_stream_connect(*this, endp))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_sock_stream_connect()
  void
  connect(const io_endp* endp) {
    ::std::error_code ec;
    connect(endp, ec);
    if (ec) throw ::std::system_error(ec, "connect");
  }

  /// @see io_sock_stream_submit_connect()
  void
  submit_connect(struct io_sock_stream_connect& connect) noexcept {
    io_sock_stream_submit_connect(*this, &connect);
  }

  /// @see io_sock_stream_submit_connect()
  template <class F>
  void
  submit_connect(const io_endp* endp, ev_exec_t* exec, F&& f) {
    return submit_connect(
        *make_stream_socket_connect_wrapper(endp, exec, ::std::forward<F>(f)));
  }

  /// @see io_sock_stream_submit_connect()
  template <class F>
  void
  submit_connect(const io_endp* endp, F&& f) {
    return submit_connect(endp, nullptr, ::std::forward<F>(f));
  }

  /// @see io_sock_stream_cancel_connect()
  bool
  cancel_connect(struct io_sock_stream_connect& connect) noexcept {
    return io_sock_stream_cancel_connect(*this, &connect) != 0;
  }

  /// @see io_sock_stream_abort_connect()
  bool
  abort_connect(struct io_sock_stream_connect& connect) noexcept {
    return io_sock_stream_abort_connect(*this, &connect) != 0;
  }

  /// @see io_sock_stream_async_connect()
  ev::Future<void, int>
  async_connect(ev_exec_t* exec, const io_endp* endp,
                struct io_sock_stream_connect** pconnect = nullptr) {
    auto future = io_sock_stream_async_connect(*this, exec, endp, pconnect);
    if (!future) util::throw_errc("async_connect");
    return ev::Future<void, int>(future);
  }

  /// @see io_sock_stream_async_connect()
  ev::Future<void, int>
  async_connect(const io_endp* endp,
                struct io_sock_stream_connect** pconnect = nullptr) {
    return async_connect(nullptr, endp, pconnect);
  }

  /// @see io_sock_stream_getpeername()
  void
  getpeername(io_endp* endp, ::std::error_code& ec) const noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_sock_stream_getpeername(*this, endp))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_sock_stream_getpeername()
  void
  getpeername(io_endp* endp = nullptr) const {
    ::std::error_code ec;
    getpeername(endp, ec);
    if (ec) throw ::std::system_error(ec, "getpeername");
  }

  /// @see io_sock_stream_recvmsg()
  template <class BufferSequence>
  ssize_t
  receive(BufferSequence& buffers, MessageFlag& flags, int timeout,
          ::std::error_code& ec) {
    detail::BufferArray buf(buffers);
    int errsv = get_errc();
    set_errc(0);
    ssize_t result =
        io_sock_stream_recvmsg(*this, buf.buf(), buf.bufcnt(),
                               reinterpret_cast<int*>(&flags), timeout);
    if (result < 0) ec = util::make_error_code();
    set_errc(errsv);
    return result;
  }

  /// @see io_sock_stream_recvmsg()
  template <class BufferSequence>
  size_t
  receive(BufferSequence& buffers, MessageFlag& flags, int timeout = -1) {
    ::std::error_code ec;
    ssize_t result = receive(buffers, flags, timeout, ec);
    if (result < 0) throw ::std::system_error(ec, "receive");
    return result;
  }

  /// @see io_sock_stream_submit_recvmsg()
  void
  submit_receive(struct io_sock_stream_recvmsg& recvmsg) noexcept {
    io_sock_stream_submit_recvmsg(*this, &recvmsg);
  }

  /// @see io_sock_stream_submit_recvmsg()
  template <class BufferSequence, class F>
  void
  submit_receive(BufferSequence& buffers, MessageFlag flags, ev_exec_t* exec,
                 F&& f) {
    submit_receive(*make_stream_socket_receive_sequence_wrapper(
        buffers, flags, exec, ::std::forward<F>(f)));
  }

  /// @see io_sock_stream_submit_recvmsg()
  template <class BufferSequence, class F>
  void
  submit_receive(BufferSequence& buffers, MessageFlag flags, F&& f) {
    submit_receive(buffers, flags, nullptr, ::std::forward<F>(f));
  }

  /// @see io_sock_stream_cancel_recvmsg()
  bool
  cancel_receive(struct io_sock_stream_recvmsg& recvmsg) noexcept {
    return io_sock_stream_cancel_recvmsg(*this, &recvmsg) != 0;
  }

  /// @see io_sock_stream_abort_recvmsg()
  bool
  abort_receive(struct io_sock_stream_recvmsg& recvmsg) noexcept {
    return io_sock_stream_abort_recvmsg(*this, &recvmsg) != 0;
  }

  /// @see io_sock_stream_async_recvmsg()
  template <class BufferSequence>
  ev::Future<ssize_t, int>
  async_receive(ev_exec_t* exec, BufferSequence& buffers, MessageFlag& flags,
                struct io_sock_stream_recvmsg** precvmsg = nullptr) {
    detail::BufferArray buf(buffers);
    auto future =
        io_sock_stream_async_recvmsg(*this, exec, buf.buf(), buf.bufcnt(),
                                     reinterpret_cast<int*>(&flags), precvmsg);
    if (!future) util::throw_errc("async_receive");
    return ev::Future<ssize_t, int>(future);
  }

  /// @see io_sock_stream_async_recvmsg()
  template <class BufferSequence>
  ev::Future<ssize_t, int>
  async_receive(BufferSequence& buffers, MessageFlag& flags,
                struct io_sock_stream_recvmsg** precvmsg = nullptr) {
    return async_receive(nullptr, buffers, flags, precvmsg);
  }

  /// @see io_sock_stream_recv()
  ssize_t
  receive(const Buffer& buffer, MessageFlag& flags, int timeout,
          ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    ssize_t result =
        io_sock_stream_recv(*this, buffer.data(), buffer.size(),
                            reinterpret_cast<int*>(&flags), timeout);
    if (result >= 0)
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
    return result;
  }

  /// @see io_sock_stream_recv()
  size_t
  receive(const Buffer& buffer, MessageFlag& flags, int timeout = -1) {
    ::std::error_code ec;
    ssize_t result = receive(buffer, flags, timeout, ec);
    if (result < 0) throw ::std::system_error(ec, "receive");
    return result;
  }

  /// @see io_sock_stream_submit_recv()
  void
  submit_receive(struct io_sock_stream_recv& recv) noexcept {
    io_sock_stream_submit_recv(*this, &recv);
  }

  /// @see io_sock_stream_submit_recv()
  template <class F>
  void
  submit_receive(const Buffer& buffer, MessageFlag flags, ev_exec_t* exec,
                 F&& f) {
    submit_receive(*make_stream_socket_receive_wrapper(buffer, flags, exec,
                                                       ::std::forward<F>(f)));
  }

  /// @see io_sock_stream_submit_recv()
  template <class F>
  void
  submit_receive(const Buffer& buffer, MessageFlag flags, F&& f) {
    submit_receive(buffer, flags, nullptr, ::std::forward<F>(f));
  }

  /// @see io_sock_stream_cancel_recv()
  bool
  cancel_receive(struct io_sock_stream_recv& recv) noexcept {
    return io_sock_stream_cancel_recv(*this, &recv) != 0;
  }

  /// @see io_sock_stream_abort_recv()
  bool
  abort_receive(struct io_sock_stream_recv& recv) noexcept {
    return io_sock_stream_abort_recv(*this, &recv) != 0;
  }

  /// @see io_sock_stream_async_recv()
  ev::Future<ssize_t, int>
  async_receive(ev_exec_t* exec, const Buffer& buffer, MessageFlag& flags,
                struct io_sock_stream_recv** precv = nullptr) {
    auto future =
        io_sock_stream_async_recv(*this, exec, buffer.data(), buffer.size(),
                                  reinterpret_cast<int*>(&flags), precv);
    if (!future) util::throw_errc("async_receive");
    return ev::Future<ssize_t, int>(future);
  }

  /// @see io_sock_stream_async_recv()
  ev::Future<ssize_t, int>
  async_receive(const Buffer& buffer, MessageFlag& flags,
                struct io_sock_stream_recv** precv = nullptr) {
    return async_receive(nullptr, buffer, flags, precv);
  }

  /// @see io_sock_stream_sendmsg()
  template <class ConstBufferSequence>
  ssize_t
  send(const ConstBufferSequence& buffers, MessageFlag flags, int timeout,
       ::std::error_code& ec) {
    detail::ConstBufferArray buf(buffers);
    int errsv = get_errc();
    set_errc(0);
    ssize_t result = io_sock_stream_sendmsg(*this, buf.buf(), buf.bufcnt(),
                                            static_cast<int>(flags), timeout);
    if (result < 0) ec = util::make_error_code();
    set_errc(errsv);
    return result;
  }

  /// @see io_sock_stream_sendmsg()
  template <class ConstBufferSequence>
  ssize_t
  send(const ConstBufferSequence& buffers,
       MessageFlag flags = MessageFlag::NONE, int timeout = -1) {
    ::std::error_code ec;
    ssize_t result = send(buffers, flags, timeout, ec);
    if (result < 0) throw ::std::system_error(ec, "send");
    return result;
  }

  /// @see io_sock_stream_submit_sendmsg()
  void
  submit_send(struct io_sock_stream_sendmsg& sendmsg) noexcept {
    io_sock_stream_submit_sendmsg(*this, &sendmsg);
  }

  /// @see io_sock_stream_submit_sendmsg()
  template <class ConstBufferSequence, class F>
  void
  submit_send(const ConstBufferSequence& buffers, MessageFlag flags,
              ev_exec_t* exec, F&& f) {
    submit_send(*make_stream_socket_send_sequence_wrapper(
        buffers, flags, exec, ::std::forward<F>(f)));
  }

  /// @see io_sock_stream_submit_sendmsg()
  template <class ConstBufferSequence, class F>
  void
  submit_send(const ConstBufferSequence& buffers, MessageFlag flags, F&& f) {
    submit_send(buffers, flags, nullptr, ::std::forward<F>(f));
  }

  /// @see io_sock_stream_cancel_sendmsg()
  bool
  cancel_send(struct io_sock_stream_sendmsg& sendmsg) noexcept {
    return io_sock_stream_cancel_sendmsg(*this, &sendmsg) != 0;
  }

  /// @see io_sock_stream_abort_sendmsg()
  bool
  abort_send(struct io_sock_stream_sendmsg& sendmsg) noexcept {
    return io_sock_stream_abort_sendmsg(*this, &sendmsg) != 0;
  }

  /// @see io_sock_stream_async_sendmsg()
  template <class ConstBufferSequence>
  ev::Future<ssize_t, int>
  async_send(ev_exec_t* exec, const ConstBufferSequence& buffers,
             MessageFlag flags = MessageFlag::NONE,
             struct io_sock_stream_sendmsg** psendmsg = nullptr) {
    detail::ConstBufferArray buf(buffers);
    auto future =
        io_sock_stream_async_sendmsg(*this, exec, buf.buf(), buf.bufcnt(),
                                     static_cast<int>(flags), psendmsg);
    if (!future) util::throw_errc("async_send");
    return ev::Future<ssize_t, int>(future);
  }

  /// @see io_sock_stream_async_sendmsg()
  template <class ConstBufferSequence>
  ev::Future<ssize_t, int>
  async_send(const ConstBufferSequence& buffers,
             MessageFlag flags = MessageFlag::NONE,
             struct io_sock_stream_sendmsg** psendmsg = nullptr) {
    return async_sendmsg(nullptr, buffers, flags, psendmsg);
  }

  /// @see io_sock_stream_send()
  ssize_t
  send(const ConstBuffer& buffer, MessageFlag flags, int timeout,
       ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    ssize_t result = io_sock_stream_send(*this, buffer.data(), buffer.size(),
                                         static_cast<int>(flags), timeout);
    if (result >= 0)
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
    return result;
  }

  /// @see io_sock_stream_send()
  size_t
  send(const ConstBuffer& buffer, MessageFlag flags = MessageFlag::NONE,
       int timeout = -1) {
    ::std::error_code ec;
    ssize_t result = send(buffer, flags, timeout, ec);
    if (result < 0) throw ::std::system_error(ec, "send");
    return result;
  }

  /// @see io_sock_stream_submit_send()
  void
  submit_send(struct io_sock_stream_send& send) noexcept {
    io_sock_stream_submit_send(*this, &send);
  }

  /// @see io_sock_stream_submit_send()
  template <class F>
  void
  submit_send(const ConstBuffer& buffer, MessageFlag flags, ev_exec_t* exec,
              F&& f) {
    submit_send(*make_stream_socket_send_wrapper(buffer, flags, exec,
                                                 ::std::forward<F>(f)));
  }

  /// @see io_sock_stream_submit_send()
  template <class F>
  void
  submit_send(const ConstBuffer& buffer, MessageFlag flags, F&& f) {
    return submit_send(buffer, flags, nullptr, ::std::forward<F>(f));
  }

  /// @see io_sock_stream_cancel_send()
  bool
  cancel_send(struct io_sock_stream_send& send) noexcept {
    return io_sock_stream_cancel_send(*this, &send) != 0;
  }

  /// @see io_sock_stream_abort_send()
  bool
  abort_send(struct io_sock_stream_send& send) noexcept {
    return io_sock_stream_abort_send(*this, &send) != 0;
  }

  /// @see io_sock_stream_async_send()
  ev::Future<ssize_t, int>
  async_send(ev_exec_t* exec, const ConstBuffer& buffer,
             MessageFlag flags = MessageFlag::NONE,
             struct io_sock_stream_send** psend = nullptr) {
    auto future =
        io_sock_stream_async_send(*this, exec, buffer.data(), buffer.size(),
                                  static_cast<int>(flags), psend);
    if (!future) util::throw_errc("async_send");
    return ev::Future<ssize_t, int>(future);
  }

  /// @see io_sock_stream_async_send()
  ev::Future<ssize_t, int>
  async_send(const ConstBuffer& buffer, MessageFlag flags = MessageFlag::NONE,
             struct io_sock_stream_send** psend = nullptr) {
    return async_send(nullptr, buffer, flags, psend);
  }

  /// @see io_sock_stream_shutdown()
  void
  shutdown(ShutdownType type, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_sock_stream_shutdown(*this, static_cast<int>(type)))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_sock_stream_shutdown()
  void
  shutdown(ShutdownType type) {
    ::std::error_code ec;
    shutdown(type, ec);
    if (ec) throw ::std::system_error(ec, "shutdown");
  }

  /// @see io_sock_stream_get_keepalive()
  bool
  keepalive(::std::error_code& ec) const noexcept {
    int errsv = get_errc();
    set_errc(0);
    int optval = io_sock_stream_get_keepalive(*this);
    if (optval >= 0)
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
    return optval > 0;
  }

  /// @see io_sock_stream_get_keepalive()
  bool
  keepalive() const {
    ::std::error_code ec;
    auto optval = keepalive(ec);
    if (ec) throw ::std::system_error(ec, "keepalive");
    return optval;
  }

  /// @see io_sock_stream_set_keepalive()
  void
  keepalive(bool optval, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_sock_stream_set_keepalive(*this, optval))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_sock_stream_set_keepalive()
  void
  keepalive(bool optval) {
    ::std::error_code ec;
    keepalive(optval, ec);
    if (ec) throw ::std::system_error(ec, "keepalive");
  }

  /// @see io_sock_stream_get_linger()
  void
  linger(bool* ponoff, int* ptimeout, ::std::error_code& ec) const noexcept {
    int errsv = get_errc();
    set_errc(0);
    int onoff = 0;
    if (!io_sock_stream_get_linger(*this, &onoff, ptimeout)) {
      if (ponoff) *ponoff = onoff != 0;
      ec.clear();
    } else {
      ec = util::make_error_code();
    }
    set_errc(errsv);
  }

  /// @see io_sock_stream_get_linger()
  bool
  linger(bool* ponoff = nullptr, int* ptimeout = nullptr) const {
    ::std::error_code ec;
    linger(ponoff, ptimeout, ec);
    if (ec) throw ::std::system_error(ec, "linger");
  }

  /// @see io_sock_stream_set_linger()
  void
  linger(bool onoff, int timeout, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_sock_stream_set_linger(*this, onoff, timeout))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_sock_stream_set_linger()
  void
  linger(bool onoff, int timeout = 0) {
    ::std::error_code ec;
    linger(onoff, timeout, ec);
    if (ec) throw ::std::system_error(ec, "linger");
  }

  /// @see io_sock_stream_get_oobinline()
  bool
  oobinline(::std::error_code& ec) const noexcept {
    int errsv = get_errc();
    set_errc(0);
    int optval = io_sock_stream_get_oobinline(*this);
    if (optval >= 0)
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
    return optval > 0;
  }

  /// @see io_sock_stream_get_oobinline()
  bool
  oobinline() const {
    ::std::error_code ec;
    auto optval = oobinline(ec);
    if (ec) throw ::std::system_error(ec, "oobinline");
    return optval;
  }

  /// @see io_sock_stream_set_oobinline()
  void
  oobinline(bool optval, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_sock_stream_set_oobinline(*this, optval))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_sock_stream_set_oobinline()
  void
  oobinline(bool optval) {
    ::std::error_code ec;
    oobinline(optval, ec);
    if (ec) throw ::std::system_error(ec, "oobinline");
  }

  /// @see io_sock_stream_atmark()
  bool
  atmark(::std::error_code& ec) const noexcept {
    int errsv = get_errc();
    set_errc(0);
    int optval = io_sock_stream_atmark(*this);
    if (optval < 0)
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
    return optval > 0;
  }

  /// @see io_sock_stream_atmark()
  bool
  atmark() const {
    ::std::error_code ec;
    auto optval = atmark(ec);
    if (ec) throw ::std::system_error(ec, "atmark");
    return optval;
  }

 protected:
  io_sock_stream_t* sock_stream{nullptr};
};

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_SOCK_STREAM_HPP_
