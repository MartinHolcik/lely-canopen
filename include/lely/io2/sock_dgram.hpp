/**@file
 * This header file is part of the I/O library; it contains the C++ interface
 * for the abstract datagram socket.
 *
 * @see lely/io2/sock_dgram.h
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

#ifndef LELY_IO2_SOCK_DGRAM_HPP_
#define LELY_IO2_SOCK_DGRAM_HPP_

#include <lely/io2/buf.hpp>
#include <lely/io2/sock.hpp>
#include <lely/io2/sock_dgram.h>

#include <utility>

namespace lely {
namespace io {

namespace detail {

template <class F>
class DatagramSocketReceiveSequenceWrapper : public io_sock_dgram_recvmsg {
 public:
  template <class BufferSequence>
  DatagramSocketReceiveSequenceWrapper(BufferSequence& buffers,
                                       MessageFlag flags, io_endp* endp,
                                       ev_exec_t* exec, F&& f)
      : io_sock_dgram_recvmsg IO_SOCK_DGRAM_RECVMSG_INIT(
            nullptr, 0, static_cast<int>(flags), endp, exec,
            [](struct ev_task * task) noexcept {
              auto recvmsg = io_sock_dgram_recvmsg_from_task(task);
              auto result = recvmsg->r.result;
              auto flags = static_cast<MessageFlag>(recvmsg->flags);
              ::std::error_code ec;
              if (result == -1) ec = util::make_error_code(recvmsg->r.errc);
              auto self =
                  static_cast<DatagramSocketReceiveSequenceWrapper*>(recvmsg);
              compat::invoke(::std::move(self->func_), result, flags, ec);
              delete self;
            }),
        buf_(buffers),
        func_(::std::forward<F>(f)) {
    buf = buf_.buf();
    bufcnt = buf_.bufcnt();
  }

  DatagramSocketReceiveSequenceWrapper(
      const DatagramSocketReceiveSequenceWrapper&) = delete;

  DatagramSocketReceiveSequenceWrapper& operator=(
      const DatagramSocketReceiveSequenceWrapper&) = delete;

  operator ev_task&() & noexcept { return task; }

 private:
  detail::BufferArray buf_;
  typename ::std::decay<F>::type func_;
};

}  // namespace detail

/**
 * Creates a vectored datagram socket receive operation with a completion task.
 * The operation deletes itself after it is completed, so it MUST NOT be deleted
 * once it is submitted to a datagram socket.
 */
template <class BufferSequence, class F>
inline typename ::std::enable_if<
    compat::is_invocable<F, ssize_t, MessageFlag, ::std::error_code>::value,
    detail::DatagramSocketReceiveSequenceWrapper<F>*>::type
make_datagram_socket_receive_sequence_wrapper(BufferSequence& buffers,
                                              MessageFlag flags, io_endp* endp,
                                              ev_exec_t* exec, F&& f) {
  return new detail::DatagramSocketReceiveSequenceWrapper<F>(
      buffers, flags, endp, exec, ::std::forward<F>(f));
}

/**
 * A vectored receive operation suitable for use with a datagram socket. This
 * class stores a callable object with signature
 * `void(ssize_t result, MessageFlag flags, std::error_code ec)`, which is
 * invoked upon completion (or cancellation) of the receive operation.
 */
class DatagramSocketReceiveSequence : public io_sock_dgram_recvmsg {
 public:
  using Signature = void(ssize_t, MessageFlag, ::std::error_code);

  /// Constructs a vectored receive operation with a completion task.
  template <class BufferSequence, class F>
  DatagramSocketReceiveSequence(BufferSequence& buffers, MessageFlag flags,
                                io_endp* endp, ev_exec_t* exec, F&& f)
      : io_sock_dgram_recvmsg IO_SOCK_DGRAM_RECVMSG_INIT(
            nullptr, 0, static_cast<int>(flags), endp, exec,
            [](struct ev_task * task) noexcept {
              auto recvmsg = io_sock_dgram_recvmsg_from_task(task);
              auto self = static_cast<DatagramSocketReceiveSequence*>(recvmsg);
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
  DatagramSocketReceiveSequence(BufferSequence& buffers, MessageFlag flags,
                                ev_exec_t* exec, F&& f)
      : DatagramSocketReceiveSequence(buffers, flags, nullptr, exec,
                                      ::std::forward<F>(f)) {}

  /// Constructs a vectored receive operation with a completion task.
  template <class BufferSequence, class F>
  DatagramSocketReceiveSequence(BufferSequence& buffers, MessageFlag flags,
                                io_endp* endp, F&& f)
      : DatagramSocketReceiveSequence(buffers, flags, endp, nullptr,
                                      ::std::forward<F>(f)) {}

  /// Constructs a vectored receive operation with a completion task.
  template <class BufferSequence, class F>
  DatagramSocketReceiveSequence(BufferSequence& buffers, MessageFlag flags,
                                F&& f)
      : DatagramSocketReceiveSequence(buffers, flags, nullptr, nullptr,
                                      ::std::forward<F>(f)) {}

  DatagramSocketReceiveSequence(const DatagramSocketReceiveSequence&) = delete;

  DatagramSocketReceiveSequence& operator=(
      const DatagramSocketReceiveSequence&) = delete;

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
class DatagramSocketReceiveWrapper : public io_sock_dgram_recvfrom {
 public:
  DatagramSocketReceiveWrapper(const Buffer& buffer, MessageFlag flags,
                               io_endp* endp, ev_exec_t* exec, F&& f)
      : io_sock_dgram_recvfrom IO_SOCK_DGRAM_RECVFROM_INIT(
            this, buffer.data(), buffer.size(), static_cast<int>(flags), endp,
            exec,
            [](ev_task * task) noexcept {
              auto recvfrom = io_sock_dgram_recvfrom_from_task(task);
              auto result = recvfrom->recvmsg.r.result;
              auto flags = static_cast<MessageFlag>(recvfrom->recvmsg.flags);
              ::std::error_code ec;
              if (result == -1)
                ec = util::make_error_code(recvfrom->recvmsg.r.errc);
              auto self = static_cast<DatagramSocketReceiveWrapper*>(recvfrom);
              compat::invoke(::std::move(self->func_), result, flags, ec);
              delete self;
            }),
        func_(::std::forward<F>(f)) {}

  DatagramSocketReceiveWrapper(const DatagramSocketReceiveWrapper&) = delete;

  DatagramSocketReceiveWrapper& operator=(const DatagramSocketReceiveWrapper&) =
      delete;

  operator ev_task&() & noexcept { return recvmsg.task; }

 private:
  typename ::std::decay<F>::type func_;
};

}  // namespace detail

/**
 * Creates a datagram socket receive operation with a completion task. The
 * operation deletes itself after it is completed, so it MUST NOT be deleted
 * once it is submitted to a datagram socket.
 */
template <class F>
inline typename ::std::enable_if<
    compat::is_invocable<F, ssize_t, MessageFlag, ::std::error_code>::value,
    detail::DatagramSocketReceiveWrapper<F>*>::type
make_datagram_socket_receive_wrapper(const Buffer& buffer, MessageFlag flags,
                                     io_endp* endp, ev_exec_t* exec, F&& f) {
  return new detail::DatagramSocketReceiveWrapper<F>(buffer, flags, endp, exec,
                                                     ::std::forward<F>(f));
}

/**
 * A receive operation suitable for use with a datagram socket. This class
 * stores a callable object with signature
 * `void(ssize_t result, MessageFlag flags, std::error_code ec)`, which is
 * invoked upon completion (or cancellation) of the receive operation.
 */
class DatagramSocketReceive : public io_sock_dgram_recvfrom {
 public:
  using Signature = void(ssize_t, MessageFlag, ::std::error_code);

  /// Constructs a receive operation with a completion task.
  template <class F>
  DatagramSocketReceive(const Buffer& buffer, MessageFlag flags, io_endp* endp,
                        ev_exec_t* exec, F&& f)
      : io_sock_dgram_recvfrom IO_SOCK_DGRAM_RECVFROM_INIT(
            this, buffer.data(), buffer.size(), static_cast<int>(flags), endp,
            exec,
            [](ev_task * task) noexcept {
              auto recvfrom = io_sock_dgram_recvfrom_from_task(task);
              auto self = static_cast<DatagramSocketReceive*>(recvfrom);
              if (self->func_) {
                auto result = recvfrom->recvmsg.r.result;
                auto flags = static_cast<MessageFlag>(recvfrom->recvmsg.flags);
                ::std::error_code ec;
                if (result == -1)
                  ec = util::make_error_code(recvfrom->recvmsg.r.errc);
                self->func_(result, flags, ec);
              }
            }),
        func_(::std::forward<F>(f)) {}

  /// Constructs a receive operation with a completion task.
  template <class F>
  DatagramSocketReceive(const Buffer& buffer, MessageFlag flags,
                        ev_exec_t* exec, F&& f)
      : DatagramSocketReceive(buffer, flags, nullptr, exec,
                              ::std::forward<F>(f)) {}

  /// Constructs a receive operation with a completion task.
  template <class F>
  DatagramSocketReceive(const Buffer& buffer, MessageFlag flags, io_endp* endp,
                        F&& f)
      : DatagramSocketReceive(buffer, flags, endp, nullptr,
                              ::std::forward<F>(f)) {}

  /// Constructs a receive operation with a completion task.
  template <class F>
  DatagramSocketReceive(const Buffer& buffer, MessageFlag flags, F&& f)
      : DatagramSocketReceive(buffer, flags, nullptr, nullptr,
                              ::std::forward<F>(f)) {}

  DatagramSocketReceive(const DatagramSocketReceive&) = delete;

  DatagramSocketReceive& operator=(const DatagramSocketReceive&) = delete;

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
class DatagramSocketSendSequenceWrapper : public io_sock_dgram_sendmsg {
 public:
  template <class ConstBufferSequence>
  DatagramSocketSendSequenceWrapper(const ConstBufferSequence& buffers,
                                    MessageFlag flags, const io_endp* endp,
                                    ev_exec_t* exec, F&& f)
      : io_sock_dgram_sendmsg IO_SOCK_DGRAM_SENDMSG_INIT(
            nullptr, 0, static_cast<int>(flags), endp, exec,
            [](struct ev_task * task) noexcept {
              auto sendmsg = io_sock_dgram_sendmsg_from_task(task);
              auto result = sendmsg->r.result;
              ::std::error_code ec;
              if (result == -1) ec = util::make_error_code(sendmsg->r.errc);
              auto self =
                  static_cast<DatagramSocketSendSequenceWrapper*>(sendmsg);
              compat::invoke(::std::move(self->func_), result, ec);
              delete self;
            }),
        buf_(buffers),
        func_(::std::forward<F>(f)) {
    buf = buf_.buf();
    bufcnt = buf_.bufcnt();
  }

  DatagramSocketSendSequenceWrapper(const DatagramSocketSendSequenceWrapper&) =
      delete;

  DatagramSocketSendSequenceWrapper& operator=(
      const DatagramSocketSendSequenceWrapper&) = delete;

  operator ev_task&() & noexcept { return task; }

 private:
  detail::ConstBufferArray buf_;
  typename ::std::decay<F>::type func_;
};

}  // namespace detail

/**
 * Creates a vectored datagram socket send operation with a completion task. The
 * operation deletes itself after it is completed, so it MUST NOT be deleted
 * once it is submitted to a datagram socket.
 */
template <class ConstBufferSequence, class F>
inline typename ::std::enable_if<
    compat::is_invocable<F, ssize_t, ::std::error_code>::value,
    detail::DatagramSocketSendSequenceWrapper<F>*>::type
make_datagram_socket_send_sequence_wrapper(const ConstBufferSequence& buffers,
                                           MessageFlag flags,
                                           const io_endp* endp, ev_exec_t* exec,
                                           F&& f) {
  return new detail::DatagramSocketSendSequenceWrapper<F>(
      buffers, flags, endp, exec, ::std::forward<F>(f));
}

/**
 * A vectored send operation suitable for use with a datagram socket. This class
 * stores a callable object with signature
 * `void(ssize_t result, std::error_code ec)`, which is invoked upon completion
 * (or cancellation) of the send operation.
 */
class DatagramSocketSendSequence : public io_sock_dgram_sendmsg {
 public:
  using Signature = void(ssize_t, ::std::error_code);

  /// Constructs a vectored send operation with a completion task.
  template <class ConstBufferSequence, class F>
  DatagramSocketSendSequence(const ConstBufferSequence& buffers,
                             MessageFlag flags, const io_endp* endp,
                             ev_exec_t* exec, F&& f)
      : io_sock_dgram_sendmsg IO_SOCK_DGRAM_SENDMSG_INIT(
            nullptr, 0, static_cast<int>(flags), endp, exec,
            [](struct ev_task * task) noexcept {
              auto sendmsg = io_sock_dgram_sendmsg_from_task(task);
              auto self = static_cast<DatagramSocketSendSequence*>(sendmsg);
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
  DatagramSocketSendSequence(const ConstBufferSequence& buffers,
                             MessageFlag flags, ev_exec_t* exec, F&& f)
      : DatagramSocketSendSequence(buffers, flags, exec, ::std::forward<F>(f)) {
  }

  /// Constructs a vectored send operation with a completion task.
  template <class ConstBufferSequence, class F>
  DatagramSocketSendSequence(const ConstBufferSequence& buffers,
                             MessageFlag flags, const io_endp* endp, F&& f)
      : DatagramSocketSendSequence(buffers, flags, endp, nullptr,
                                   ::std::forward<F>(f)) {}

  /// Constructs a vectored send operation with a completion task.
  template <class ConstBufferSequence, class F>
  DatagramSocketSendSequence(const ConstBufferSequence& buffers,
                             MessageFlag flags, F&& f)
      : DatagramSocketSendSequence(buffers, flags, nullptr, nullptr,
                                   ::std::forward<F>(f)) {}

  DatagramSocketSendSequence(const DatagramSocketSendSequence&) = delete;

  DatagramSocketSendSequence& operator=(const DatagramSocketSendSequence&) =
      delete;

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
class DatagramSocketSendWrapper : public io_sock_dgram_sendto {
 public:
  DatagramSocketSendWrapper(const ConstBuffer& buffer, MessageFlag flags,
                            const io_endp* endp, ev_exec_t* exec, F&& f)
      : io_sock_dgram_sendto IO_SOCK_DGRAM_SENDTO_INIT(
            this, buffer.data(), buffer.size(), static_cast<int>(flags), endp,
            exec,
            [](ev_task * task) noexcept {
              auto sendto = io_sock_dgram_sendto_from_task(task);
              auto result = sendto->sendmsg.r.result;
              ::std::error_code ec;
              if (result == -1)
                ec = util::make_error_code(sendto->sendmsg.r.errc);
              auto self = static_cast<DatagramSocketSendWrapper*>(sendto);
              compat::invoke(::std::move(self->func_), result, ec);
              delete self;
            }),
        func_(::std::forward<F>(f)) {}

  DatagramSocketSendWrapper(const DatagramSocketSendWrapper&) = delete;

  DatagramSocketSendWrapper& operator=(const DatagramSocketSendWrapper&) =
      delete;

  operator ev_task&() & noexcept { return sendmsg.task; }

 private:
  typename ::std::decay<F>::type func_;
};

}  // namespace detail

/**
 * Creates a datagram socket send operation with a completion task. The
 * operation deletes itself after it is completed, so it MUST NOT be deleted
 * once it is submitted to a datagram socket.
 */
template <class F>
inline typename ::std::enable_if<
    compat::is_invocable<F, ssize_t, ::std::error_code>::value,
    detail::DatagramSocketSendWrapper<F>*>::type
make_datagram_socket_send_wrapper(const ConstBuffer& buffer, MessageFlag flags,
                                  const io_endp* endp, ev_exec_t* exec, F&& f) {
  return new detail::DatagramSocketSendWrapper<F>(buffer, flags, endp, exec,
                                                  ::std::forward<F>(f));
}

/**
 * A send operation suitable for use with a datagram socket. This class stores a
 * callable object with signature `void(ssize_t result, std::error_code ec)`,
 * which is invoked upon completion (or cancellation) of the send operation.
 */
class DatagramSocketSend : public io_sock_dgram_sendto {
 public:
  using Signature = void(ssize_t, ::std::error_code);

  /// Constructs a send operation with a completion task.
  template <class F>
  DatagramSocketSend(const ConstBuffer& buffer, MessageFlag flags,
                     const io_endp* endp, ev_exec_t* exec, F&& f)
      : io_sock_dgram_sendto IO_SOCK_DGRAM_SENDTO_INIT(
            this, buffer.data(), buffer.size(), static_cast<int>(flags), endp,
            exec,
            [](ev_task * task) noexcept {
              auto sendto = io_sock_dgram_sendto_from_task(task);
              auto self = static_cast<DatagramSocketSend*>(sendto);
              if (self->func_) {
                auto result = sendto->sendmsg.r.result;
                ::std::error_code ec;
                if (result == -1)
                  ec = util::make_error_code(sendto->sendmsg.r.errc);
                self->func_(result, ec);
              }
            }),
        func_(::std::forward<F>(f)) {}

  /// Constructs a send operation with a completion task.
  template <class F>
  DatagramSocketSend(const ConstBuffer& buffer, MessageFlag flags,
                     ev_exec_t* exec, F&& f)
      : DatagramSocketSend(buffer, flags, nullptr, exec, ::std::forward<F>(f)) {
  }

  /// Constructs a send operation with a completion task.
  template <class F>
  DatagramSocketSend(const ConstBuffer& buffer, MessageFlag flags,
                     const io_endp* endp, F&& f)
      : DatagramSocketSend(buffer, flags, endp, nullptr, ::std::forward<F>(f)) {
  }

  /// Constructs a send operation with a completion task.
  template <class F>
  DatagramSocketSend(const ConstBuffer& buffer, MessageFlag flags, F&& f)
      : DatagramSocketSend(buffer, flags, nullptr, nullptr,
                           ::std::forward<F>(f)) {}

  DatagramSocketSend(const DatagramSocketSend&) = delete;

  DatagramSocketSend& operator=(const DatagramSocketSend&) = delete;

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
 * A reference to a datagram socket. This class is a wrapper around
 * `#io_sock_dgram_t*`.
 */
class DatagramSocketBase : public SocketBase {
 public:
  using SocketBase::operator io_sock_t*;

  explicit DatagramSocketBase(io_sock_dgram_t* sock_dgram_) noexcept
      : Device(sock_dgram_ ? io_sock_dgram_get_dev(sock_dgram_) : nullptr),
        SocketBase(sock_dgram_ ? io_sock_dgram_get_sock(sock_dgram_) : nullptr),
        sock_dgram(sock_dgram_) {}

  operator io_sock_dgram_t*() const noexcept { return sock_dgram; }

  /// @see io_sock_dgram_connect()
  void
  connect(const io_endp* endp, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_sock_dgram_connect(*this, endp))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_sock_dgram_connect()
  void
  connect(const io_endp* endp) {
    ::std::error_code ec;
    connect(endp, ec);
    if (ec) throw ::std::system_error(ec, "connect");
  }

  /// @see io_sock_dgram_connect()
  void
  disconnect(::std::error_code& ec) noexcept {
    connect(nullptr, ec);
  }

  /// @see io_sock_dgram_connect()
  void
  disconnect() {
    connect(nullptr);
  }

  /// @see io_sock_dgram_getpeername()
  void
  getpeername(io_endp* endp, ::std::error_code& ec) const noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_sock_dgram_getpeername(*this, endp))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_sock_dgram_getpeername()
  void
  getpeername(io_endp* endp = nullptr) const {
    ::std::error_code ec;
    getpeername(endp, ec);
    if (ec) throw ::std::system_error(ec, "getpeername");
  }

  /// @see io_sock_dgram_recvmsg()
  template <class BufferSequence>
  ssize_t
  receive(BufferSequence& buffers, MessageFlag& flags, io_endp* endp,
          int timeout, ::std::error_code& ec) {
    detail::BufferArray buf(buffers);
    int errsv = get_errc();
    set_errc(0);
    ssize_t result =
        io_sock_dgram_recvmsg(*this, buf.buf(), buf.bufcnt(),
                              reinterpret_cast<int*>(&flags), endp, timeout);
    if (result < 0) ec = util::make_error_code();
    set_errc(errsv);
    return result;
  }

  /// @see io_sock_dgram_recvmsg()
  template <class BufferSequence>
  ssize_t
  receive(BufferSequence& buffers, MessageFlag& flags, int timeout,
          ::std::error_code& ec) {
    return receive(buffers, flags, nullptr, timeout, ec);
  }

  /// @see io_sock_dgram_recvmsg()
  template <class BufferSequence>
  size_t
  receive(BufferSequence& buffers, MessageFlag& flags, io_endp* endp = nullptr,
          int timeout = -1) {
    ::std::error_code ec;
    ssize_t result = receive(buffers, flags, endp, timeout, ec);
    if (result < 0) throw ::std::system_error(ec, "receive");
    return result;
  }

  /// @see io_sock_dgram_submit_recvmsg()
  void
  submit_receive(struct io_sock_dgram_recvmsg& recvmsg) noexcept {
    io_sock_dgram_submit_recvmsg(*this, &recvmsg);
  }

  /// @see io_sock_dgram_submit_recvmsg()
  template <class BufferSequence, class F>
  void
  submit_receive(BufferSequence& buffers, MessageFlag flags, io_endp* endp,
                 ev_exec_t* exec, F&& f) {
    submit_receive(*make_datagram_socket_receive_sequence_wrapper(
        buffers, flags, endp, exec, ::std::forward<F>(f)));
  }

  /// @see io_sock_dgram_submit_recvmsg()
  template <class BufferSequence, class F>
  void
  submit_receive(BufferSequence& buffers, MessageFlag flags, ev_exec_t* exec,
                 F&& f) {
    submit_receive(buffers, flags, nullptr, exec, ::std::forward<F>(f));
  }

  /// @see io_sock_dgram_submit_recvmsg()
  template <class BufferSequence, class F>
  void
  submit_receive(BufferSequence& buffers, MessageFlag flags, io_endp* endp,
                 F&& f) {
    submit_receive(buffers, flags, endp, nullptr, ::std::forward<F>(f));
  }

  /// @see io_sock_dgram_submit_recvmsg()
  template <class BufferSequence, class F>
  void
  submit_receive(BufferSequence& buffers, MessageFlag flags, F&& f) {
    submit_receive(buffers, flags, nullptr, nullptr, ::std::forward<F>(f));
  }

  /// @see io_sock_dgram_cancel_recvmsg()
  bool
  cancel_receive(struct io_sock_dgram_recvmsg& recvmsg) noexcept {
    return io_sock_dgram_cancel_recvmsg(*this, &recvmsg) != 0;
  }

  /// @see io_sock_dgram_abort_recvmsg()
  bool
  abort_receive(struct io_sock_dgram_recvmsg& recvmsg) noexcept {
    return io_sock_dgram_abort_recvmsg(*this, &recvmsg) != 0;
  }

  /// @see io_sock_dgram_async_recvmsg()
  template <class BufferSequence>
  ev::Future<ssize_t, int>
  async_receive(ev_exec_t* exec, BufferSequence& buffers, MessageFlag& flags,
                io_endp* endp = nullptr,
                struct io_sock_dgram_recvmsg** precvmsg = nullptr) {
    detail::BufferArray buf(buffers);
    auto future = io_sock_dgram_async_recvmsg(
        *this, exec, buf.buf(), buf.bufcnt(), reinterpret_cast<int*>(&flags),
        endp, precvmsg);
    if (!future) util::throw_errc("async_receive");
    return ev::Future<ssize_t, int>(future);
  }

  /// @see io_sock_dgram_async_recvmsg()
  template <class BufferSequence>
  ev::Future<ssize_t, int>
  async_receive(BufferSequence& buffers, MessageFlag& flags,
                io_endp* endp = nullptr,
                struct io_sock_dgram_recvmsg** precvmsg = nullptr) {
    return async_receive(nullptr, buffers, flags, endp, precvmsg);
  }

  /// @see io_sock_dgram_recvfrom()
  ssize_t
  receive(const Buffer& buffer, MessageFlag& flags, io_endp* endp, int timeout,
          ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    ssize_t result =
        io_sock_dgram_recvfrom(*this, buffer.data(), buffer.size(),
                               reinterpret_cast<int*>(&flags), endp, timeout);
    if (result >= 0)
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
    return result;
  }

  /// @see io_sock_dgram_recvfrom()
  ssize_t
  receive(const Buffer& buffer, MessageFlag& flags, int timeout,
          ::std::error_code& ec) noexcept {
    return receive(buffer, flags, nullptr, timeout, ec);
  }

  /// @see io_sock_dgram_recvfrom()
  size_t
  receive(const Buffer& buffer, MessageFlag& flags, io_endp* endp = nullptr,
          int timeout = -1) {
    ::std::error_code ec;
    ssize_t result = receive(buffer, flags, endp, timeout, ec);
    if (result < 0) throw ::std::system_error(ec, "receive");
    return result;
  }

  /// @see io_sock_dgram_submit_recvfrom()
  void
  submit_receive(struct io_sock_dgram_recvfrom& recvfrom) noexcept {
    io_sock_dgram_submit_recvfrom(*this, &recvfrom);
  }

  /// @see io_sock_dgram_submit_recvfrom()
  template <class F>
  void
  submit_receive(const Buffer& buffer, MessageFlag flags, io_endp* endp,
                 ev_exec_t* exec, F&& f) {
    submit_receive(*make_datagram_socket_receive_wrapper(
        buffer, flags, endp, exec, ::std::forward<F>(f)));
  }

  /// @see io_sock_dgram_submit_recvfrom()
  template <class F>
  void
  submit_receive(const Buffer& buffer, MessageFlag flags, ev_exec_t* exec,
                 F&& f) {
    submit_receive(buffer, flags, nullptr, exec, ::std::forward<F>(f));
  }

  /// @see io_sock_dgram_submit_recvfrom()
  template <class F>
  void
  submit_receive(const Buffer& buffer, MessageFlag flags, io_endp* endp,
                 F&& f) {
    submit_receive(buffer, flags, endp, nullptr, ::std::forward<F>(f));
  }

  /// @see io_sock_dgram_submit_recvfrom()
  template <class F>
  void
  submit_receive(const Buffer& buffer, MessageFlag flags, F&& f) {
    submit_receive(buffer, flags, nullptr, nullptr, ::std::forward<F>(f));
  }

  /// @see io_sock_dgram_cancel_recvfrom()
  bool
  cancel_receive(struct io_sock_dgram_recvfrom& recvfrom) noexcept {
    return io_sock_dgram_cancel_recvfrom(*this, &recvfrom) != 0;
  }

  /// @see io_sock_dgram_abort_recvfrom()
  bool
  abort_receive(struct io_sock_dgram_recvfrom& recvfrom) noexcept {
    return io_sock_dgram_abort_recvfrom(*this, &recvfrom) != 0;
  }

  /// @see io_sock_dgram_async_recvfrom()
  ev::Future<ssize_t, int>
  async_receive(ev_exec_t* exec, const Buffer& buffer, MessageFlag& flags,
                io_endp* endp = nullptr,
                struct io_sock_dgram_recvfrom** precvfrom = nullptr) {
    auto future = io_sock_dgram_async_recvfrom(
        *this, exec, buffer.data(), buffer.size(),
        reinterpret_cast<int*>(&flags), endp, precvfrom);
    if (!future) util::throw_errc("async_receive");
    return ev::Future<ssize_t, int>(future);
  }

  /// @see io_sock_dgram_async_recvfrom()
  ev::Future<ssize_t, int>
  async_receive(const Buffer& buffer, MessageFlag& flags,
                io_endp* endp = nullptr,
                struct io_sock_dgram_recvfrom** precvfrom = nullptr) {
    return async_receive(nullptr, buffer, flags, endp, precvfrom);
  }

  /// @see io_sock_dgram_sendmsg()
  template <class ConstBufferSequence>
  ssize_t
  send(const ConstBufferSequence& buffers, MessageFlag flags,
       const io_endp* endp, int timeout, ::std::error_code& ec) {
    detail::ConstBufferArray buf(buffers);
    int errsv = get_errc();
    set_errc(0);
    ssize_t result = io_sock_dgram_sendmsg(
        *this, buf.buf(), buf.bufcnt(), static_cast<int>(flags), timeout, endp);
    if (result < 0) ec = util::make_error_code();
    set_errc(errsv);
    return result;
  }

  /// @see io_sock_dgram_sendmsg()
  template <class ConstBufferSequence>
  ssize_t
  send(const ConstBufferSequence& buffers, MessageFlag flags, int timeout,
       ::std::error_code& ec) {
    return send(buffers, flags, nullptr, timeout, ec);
  }

  /// @see io_sock_dgram_sendmsg()
  template <class ConstBufferSequence>
  ssize_t
  send(const ConstBufferSequence& buffers,
       MessageFlag flags = MessageFlag::NONE, const io_endp* endp = nullptr,
       int timeout = -1) {
    ::std::error_code ec;
    ssize_t result = send(buffers, flags, endp, timeout, ec);
    if (result < 0) throw ::std::system_error(ec, "send");
    return result;
  }

  /// @see io_sock_dgram_submit_sendmsg()
  void
  submit_send(struct io_sock_dgram_sendmsg& sendmsg) noexcept {
    io_sock_dgram_submit_sendmsg(*this, &sendmsg);
  }

  /// @see io_sock_dgram_submit_sendmsg()
  template <class ConstBufferSequence, class F>
  void
  submit_send(const ConstBufferSequence& buffers, MessageFlag flags,
              const io_endp* endp, ev_exec_t* exec, F&& f) {
    submit_send(*make_datagram_socket_send_sequence_wrapper(
        buffers, flags, endp, exec, ::std::forward<F>(f)));
  }

  /// @see io_sock_dgram_submit_sendmsg()
  template <class ConstBufferSequence, class F>
  void
  submit_send(const ConstBufferSequence& buffers, MessageFlag flags,
              ev_exec_t* exec, F&& f) {
    submit_send(buffers, flags, nullptr, exec, ::std::forward<F>(f));
  }

  /// @see io_sock_dgram_submit_sendmsg()
  template <class ConstBufferSequence, class F>
  void
  submit_send(const ConstBufferSequence& buffers, MessageFlag flags,
              const io_endp* endp, F&& f) {
    submit_send(buffers, flags, endp, nullptr, ::std::forward<F>(f));
  }

  /// @see io_sock_dgram_submit_sendmsg()
  template <class ConstBufferSequence, class F>
  void
  submit_send(const ConstBufferSequence& buffers, MessageFlag flags, F&& f) {
    submit_send(buffers, flags, nullptr, nullptr, ::std::forward<F>(f));
  }

  /// @see io_sock_dgram_cancel_sendmsg()
  bool
  cancel_send(struct io_sock_dgram_sendmsg& sendmsg) noexcept {
    return io_sock_dgram_cancel_sendmsg(*this, &sendmsg) != 0;
  }

  /// @see io_sock_dgram_abort_sendmsg()
  bool
  abort_send(struct io_sock_dgram_sendmsg& sendmsg) noexcept {
    return io_sock_dgram_abort_sendmsg(*this, &sendmsg) != 0;
  }

  /// @see io_sock_dgram_async_sendmsg()
  template <class ConstBufferSequence>
  ev::Future<ssize_t, int>
  async_send(ev_exec_t* exec, const ConstBufferSequence& buffers,
             MessageFlag flags = MessageFlag::NONE,
             const io_endp* endp = nullptr,
             struct io_sock_dgram_sendmsg** psendmsg = nullptr) {
    detail::ConstBufferArray buf(buffers);
    auto future =
        io_sock_dgram_async_sendmsg(*this, exec, buf.buf(), buf.bufcnt(),
                                    static_cast<int>(flags), endp, psendmsg);
    if (!future) util::throw_errc("async_send");
    return ev::Future<ssize_t, int>(future);
  }

  /// @see io_sock_dgram_async_sendmsg()
  template <class ConstBufferSequence>
  ev::Future<ssize_t, int>
  async_send(const ConstBufferSequence& buffers,
             MessageFlag flags = MessageFlag::NONE,
             const io_endp* endp = nullptr,
             struct io_sock_dgram_sendmsg** psendmsg = nullptr) {
    return async_sendmsg(nullptr, buffers, flags, endp, psendmsg);
  }

  /// @see io_sock_dgram_sendto()
  ssize_t
  send(const ConstBuffer& buffer, MessageFlag flags, const io_endp* endp,
       int timeout, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    ssize_t result =
        io_sock_dgram_sendto(*this, buffer.data(), buffer.size(),
                             static_cast<int>(flags), endp, timeout);
    if (result >= 0)
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
    return result;
  }

  /// @see io_sock_dgram_sendto()
  ssize_t
  send(const ConstBuffer& buffer, MessageFlag flags, int timeout,
       ::std::error_code& ec) noexcept {
    return send(buffer, flags, nullptr, timeout, ec);
  }

  /// @see io_sock_dgram_sendto()
  size_t
  send(const ConstBuffer& buffer, MessageFlag flags = MessageFlag::NONE,
       const io_endp* endp = nullptr, int timeout = -1) {
    ::std::error_code ec;
    ssize_t result = send(buffer, flags, endp, timeout, ec);
    if (result < 0) throw ::std::system_error(ec, "send");
    return result;
  }

  /// @see io_sock_dgram_submit_sendto()
  void
  submit_send(struct io_sock_dgram_sendto& sendto) noexcept {
    io_sock_dgram_submit_sendto(*this, &sendto);
  }

  /// @see io_sock_dgram_submit_sendto()
  template <class F>
  void
  submit_send(const ConstBuffer& buffer, const io_endp* endp, ev_exec_t* exec,
              MessageFlag flags, F&& f) {
    submit_send(*make_datagram_socket_send_wrapper(buffer, flags, endp, exec,
                                                   ::std::forward<F>(f)));
  }

  /// @see io_sock_dgram_submit_sendto()
  template <class F>
  void
  submit_send(const ConstBuffer& buffer, ev_exec_t* exec, MessageFlag flags,
              F&& f) {
    return submit_send(buffer, flags, nullptr, exec, ::std::forward<F>(f));
  }

  /// @see io_sock_dgram_submit_sendto()
  template <class F>
  void
  submit_send(const ConstBuffer& buffer, const io_endp* endp, MessageFlag flags,
              F&& f) {
    return submit_send(buffer, flags, endp, nullptr, ::std::forward<F>(f));
  }

  /// @see io_sock_dgram_submit_sendto()
  template <class F>
  void
  submit_send(const ConstBuffer& buffer, MessageFlag flags, F&& f) {
    return submit_send(buffer, flags, nullptr, nullptr, ::std::forward<F>(f));
  }

  /// @see io_sock_dgram_cancel_sendto()
  bool
  cancel_send(struct io_sock_dgram_sendto& sendto) noexcept {
    return io_sock_dgram_cancel_sendto(*this, &sendto) != 0;
  }

  /// @see io_sock_dgram_abort_sendto()
  bool
  abort_send(struct io_sock_dgram_sendto& sendto) noexcept {
    return io_sock_dgram_abort_sendto(*this, &sendto) != 0;
  }

  /// @see io_sock_dgram_async_sendto()
  ev::Future<ssize_t, int>
  async_send(ev_exec_t* exec, const ConstBuffer& buffer,
             MessageFlag flags = MessageFlag::NONE,
             const io_endp* endp = nullptr,
             struct io_sock_dgram_sendto** psendto = nullptr) {
    auto future =
        io_sock_dgram_async_sendto(*this, exec, buffer.data(), buffer.size(),
                                   static_cast<int>(flags), endp, psendto);
    if (!future) util::throw_errc("async_send");
    return ev::Future<ssize_t, int>(future);
  }

  /// @see io_sock_dgram_async_send()
  ev::Future<ssize_t, int>
  async_send(const ConstBuffer& buffer, MessageFlag flags = MessageFlag::NONE,
             const io_endp* endp = nullptr,
             struct io_sock_dgram_sendto** psendto = nullptr) {
    return async_send(nullptr, buffer, flags, endp, psendto);
  }

  /// @see io_sock_dgram_get_broadcast()
  bool
  broadcast(::std::error_code& ec) const noexcept {
    int errsv = get_errc();
    set_errc(0);
    int optval = io_sock_dgram_get_broadcast(*this);
    if (optval >= 0)
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
    return optval > 0;
  }

  /// @see io_sock_dgram_get_broadcast()
  bool
  broadcast() const {
    ::std::error_code ec;
    auto optval = broadcast(ec);
    if (ec) throw ::std::system_error(ec, "broadcast");
    return optval;
  }

  /// @see io_sock_dgram_set_broadcast()
  void
  broadcast(bool optval, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_sock_dgram_set_broadcast(*this, optval))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_sock_dgram_set_broadcast()
  void
  broadcast(bool optval) {
    ::std::error_code ec;
    broadcast(optval, ec);
    if (ec) throw ::std::system_error(ec, "broadcast");
  }

 protected:
  io_sock_dgram_t* sock_dgram{nullptr};
};

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_SOCK_DGRAM_HPP_
