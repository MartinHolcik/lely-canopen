/**@file
 * This header file is part of the I/O library; it contains the base class for
 * stream socket connect, send and receive operations with a stackless coroutine
 * as the completion task.
 *
 * @see lely/util/coroutine.hpp, lely/io2/sock_stream.hpp
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

#ifndef LELY_IO2_CO_SOCK_STREAM_HPP_
#define LELY_IO2_CO_SOCK_STREAM_HPP_

#include <lely/io2/co_sock.hpp>
#include <lely/io2/co_stream.hpp>
#include <lely/io2/sock_stream.hpp>

namespace lely {
namespace io {

/**
 * A stream socket connect operation with a stackless coroutine as the
 * completion task.
 */
class CoStreamSocketConnect : public io_sock_stream_connect,
                              public util::Coroutine {
 public:
  /// Constructs a connect operation.
  CoStreamSocketConnect(const io_endp* endp, ev_exec_t* exec = nullptr) noexcept
      : io_sock_stream_connect
        IO_SOCK_STREAM_CONNECT_INIT(endp, exec, [](ev_task * task) noexcept {
          auto connect = io_sock_stream_connect_from_task(task);
          ::std::error_code ec = util::make_error_code(connect->errc);
          auto self = static_cast<CoStreamSocketConnect*>(connect);
          (*self)(ec);
        }) {}

  virtual ~CoStreamSocketConnect() = default;

  operator ev_task&() & noexcept { return task; }

  /// Returns the executor to which the completion task is (to be) submitted.
  ev::Executor
  get_executor() const noexcept {
    return ev::Executor(task.exec);
  }

  /**
   * The coroutine to be executed once the connect operation completes (or is
   * canceled).
   *
   * @param ec the error code if an error occurred or the operation was
   *           canceled.
   */
  virtual void operator()(::std::error_code ec) noexcept = 0;
};

/**
 * A vectored stream socket receive operation with a stackless coroutine as the
 * completion task.
 */
class CoStreamSocketReceiveSequence : public io_sock_stream_recvmsg,
                                      public util::Coroutine {
 public:
  /// Constructs a vectored receive operation.
  template <class BufferSequence>
  CoStreamSocketReceiveSequence(BufferSequence& buffers, MessageFlag flags,
                                ev_exec_t* exec = nullptr) noexcept
      : io_sock_stream_recvmsg IO_SOCK_STREAM_RECVMSG_INIT(
            nullptr, 0, static_cast<int>(flags), exec,
            [](struct ev_task * task) noexcept {
              auto recvmsg = io_sock_stream_recvmsg_from_task(task);
              auto result = recvmsg->r.result;
              auto flags = static_cast<MessageFlag>(recvmsg->flags);
              ::std::error_code ec;
              if (result == -1) ec = util::make_error_code(recvmsg->r.errc);
              auto self = static_cast<CoStreamSocketReceiveSequence*>(recvmsg);
              (*self)(result, flags, ec);
            }),
        buf_(buffers) {
    buf = buf_.buf();
    bufcnt = buf_.bufcnt();
  }

  CoStreamSocketReceiveSequence(
      const CoStreamSocketReceiveSequence& recvmsg) noexcept
      : io_sock_stream_recvmsg(recvmsg),
        Coroutine(recvmsg),
        buf_(recvmsg.buf_) {
    buf = buf_.buf();
  }

  CoStreamSocketReceiveSequence&
  operator=(const CoStreamSocketReceiveSequence& recvmsg) noexcept {
    if (this != &recvmsg) {
      io_sock_stream_recvmsg::operator=(recvmsg);
      Coroutine::operator=(recvmsg);
      buf_ = recvmsg.buf_;
      buf = buf_.buf();
    }
    return *this;
  }

  virtual ~CoStreamSocketReceiveSequence() = default;

  operator ev_task&() & noexcept { return task; }

  /// Returns the executor to which the completion task is (to be) submitted.
  ev::Executor
  get_executor() const noexcept {
    return ev::Executor(task.exec);
  }

  /**
   * The coroutine to be executed once the receive operation completes (or is
   * canceled).
   *
   * @param result the number of bytes received on success, 0 when the peer has
   *               performed an orderly shutdown, or -1 on error (or if the
   *               operation is canceled).
   * @param flags  the flags set by the receive operation (may be
   *               #MessageFlags::OOB).
   * @param ec     the error code, or 0 on success.
   */
  virtual void operator()(ssize_t result, MessageFlag flags,
                          ::std::error_code ec) noexcept = 0;

 private:
  detail::BufferArray buf_;
};

/**
 * A stream socket receive operation with a stackless coroutine as the
 * completion task.
 */
class CoStreamSocketReceive : public io_sock_stream_recv,
                              public util::Coroutine {
 public:
  /// Constructs a receive operation.
  CoStreamSocketReceive(const Buffer& buffer, MessageFlag flags,
                        ev_exec_t* exec = nullptr) noexcept
      : io_sock_stream_recv IO_SOCK_STREAM_RECV_INIT(
            this, buffer.data(), buffer.size(), static_cast<int>(flags),
            exec, [](ev_task * task) noexcept {
              auto recv = io_sock_stream_recv_from_task(task);
              ::std::error_code ec;
              auto result = recv->recvmsg.r.result;
              auto flags = static_cast<MessageFlag>(recv->recvmsg.flags);
              if (result == -1)
                ec = util::make_error_code(recv->recvmsg.r.errc);
              auto self = static_cast<CoStreamSocketReceive*>(recv);
              (*self)(result, flags, ec);
            }) {}

  virtual ~CoStreamSocketReceive() = default;

  operator ev_task&() & noexcept { return recvmsg.task; }

  /// Returns the executor to which the completion task is (to be) submitted.
  ev::Executor
  get_executor() const noexcept {
    return ev::Executor(recvmsg.task.exec);
  }

  /**
   * The coroutine to be executed once the receive operation completes (or is
   * canceled).
   *
   * @param result the number of bytes received on success, 0 when the peer has
   *               performed an orderly shutdown, or -1 on error (or if the
   *               operation is canceled).
   * @param flags  the flags set by the receive operation (may be
   *               #MessageFlags::OOB).
   * @param ec     the error code, or 0 on success.
   */
  virtual void operator()(ssize_t result, MessageFlag flags,
                          ::std::error_code ec) noexcept = 0;
};

/**
 * A vectored stream socket send operation with a stackless coroutine as the
 * completion task.
 */
class CoStreamSocketSendSequence : public io_sock_stream_sendmsg,
                                   public util::Coroutine {
 public:
  /// Constructs a vectored send operation.
  template <class ConstBufferSequence>
  CoStreamSocketSendSequence(const ConstBufferSequence& buffers,
                             MessageFlag flags,
                             ev_exec_t* exec = nullptr) noexcept
      : io_sock_stream_sendmsg IO_SOCK_STREAM_SENDMSG_INIT(
            nullptr, 0, static_cast<int>(flags), exec,
            [](struct ev_task * task) noexcept {
              auto sendmsg = io_sock_stream_sendmsg_from_task(task);
              auto result = sendmsg->r.result;
              ::std::error_code ec;
              if (result == -1) ec = util::make_error_code(sendmsg->r.errc);
              auto self = static_cast<CoStreamSocketSendSequence*>(sendmsg);
              (*self)(result, ec);
            }),
        buf_(buffers) {
    buf = buf_.buf();
    bufcnt = buf_.bufcnt();
  }

  CoStreamSocketSendSequence(const CoStreamSocketSendSequence& sendmsg) noexcept
      : io_sock_stream_sendmsg(sendmsg),
        Coroutine(sendmsg),
        buf_(sendmsg.buf_) {
    buf = buf_.buf();
  }

  CoStreamSocketSendSequence&
  operator=(const CoStreamSocketSendSequence& sendmsg) noexcept {
    if (this != &sendmsg) {
      io_sock_stream_sendmsg::operator=(sendmsg);
      Coroutine::operator=(sendmsg);
      buf_ = sendmsg.buf_;
      buf = buf_.buf();
    }
    return *this;
  }

  virtual ~CoStreamSocketSendSequence() = default;

  operator ev_task&() & noexcept { return task; }

  /// Returns the executor to which the completion task is (to be) submitted.
  ev::Executor
  get_executor() const noexcept {
    return ev::Executor(task.exec);
  }

  /**
   * The coroutine to be executed once the send operation completes (or is
   * canceled).
   *
   * @param result the number of bytes sent on success, or -1 on error (or if
   *               the operation is canceled).
   * @param ec     the error code, or 0 on success.
   */
  virtual void operator()(ssize_t result, ::std::error_code ec) noexcept = 0;

 private:
  detail::ConstBufferArray buf_;
};

/**
 * A stream socket send operation with a stackless coroutine as the completion
 * task.
 */
class CoStreamSocketSend : public io_sock_stream_send, public util::Coroutine {
 public:
  /// Constructs a send operation.
  CoStreamSocketSend(const ConstBuffer& buffer, MessageFlag flags,
                     ev_exec_t* exec = nullptr) noexcept
      : io_sock_stream_send IO_SOCK_STREAM_SEND_INIT(
            this, buffer.data(), buffer.size(), static_cast<int>(flags),
            exec, [](ev_task * task) noexcept {
              auto send = io_sock_stream_send_from_task(task);
              ::std::error_code ec;
              auto result = send->sendmsg.r.result;
              if (result == -1)
                ec = util::make_error_code(send->sendmsg.r.errc);
              auto self = static_cast<CoStreamSocketSend*>(send);
              (*self)(result, ec);
            }) {}

  virtual ~CoStreamSocketSend() = default;

  operator ev_task&() & noexcept { return sendmsg.task; }

  /// Returns the executor to which the completion task is (to be) submitted.
  ev::Executor
  get_executor() const noexcept {
    return ev::Executor(sendmsg.task.exec);
  }

  /**
   * The coroutine to be executed once the send operation completes (or is
   * canceled).
   *
   * @param result the number of bytes sent on success, or -1 on error (or if
   *               the operation is canceled).
   * @param ec     the error code, or 0 on success.
   */
  virtual void operator()(ssize_t result, ::std::error_code ec) noexcept = 0;
};

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_CO_SOCK_STREAM_HPP_
