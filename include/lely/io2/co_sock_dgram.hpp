/**@file
 * This header file is part of the I/O library; it contains the base class for
 * datagram socket send and receive operations with a stackless coroutine as the
 * completion task.
 *
 * @see lely/util/coroutine.hpp, lely/io2/sock_dgram.hpp
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

#ifndef LELY_IO2_CO_SOCK_DGRAM_HPP_
#define LELY_IO2_CO_SOCK_DGRAM_HPP_

#include <lely/io2/co_sock.hpp>
#include <lely/io2/sock_dgram.hpp>

namespace lely {
namespace io {

/**
 * A vectored datagram socket receive operation with a stackless coroutine as
 * the completion task.
 */
class CoDatagramSocketReceiveSequence : public io_sock_dgram_recvmsg,
                                        public util::Coroutine {
 public:
  /// Constructs a vectored receive operation.
  template <class BufferSequence>
  CoDatagramSocketReceiveSequence(BufferSequence& buffers, MessageFlag flags,
                                  io_endp* endp = nullptr,
                                  ev_exec_t* exec = nullptr) noexcept
      : io_sock_dgram_recvmsg IO_SOCK_DGRAM_RECVMSG_INIT(
            nullptr, 0, static_cast<int>(flags), endp, exec,
            [](struct ev_task * task) noexcept {
              auto recvmsg = io_sock_dgram_recvmsg_from_task(task);
              auto result = recvmsg->r.result;
              auto flags = static_cast<MessageFlag>(recvmsg->flags);
              ::std::error_code ec;
              if (result == -1) ec = util::make_error_code(recvmsg->r.errc);
              auto self =
                  static_cast<CoDatagramSocketReceiveSequence*>(recvmsg);
              (*self)(result, flags, ec);
            }),
        buf_(buffers) {
    buf = buf_.buf();
    bufcnt = buf_.bufcnt();
  }

  CoDatagramSocketReceiveSequence(
      const CoDatagramSocketReceiveSequence& recvmsg) noexcept
      : io_sock_dgram_recvmsg(recvmsg), Coroutine(recvmsg), buf_(recvmsg.buf_) {
    buf = buf_.buf();
  }

  CoDatagramSocketReceiveSequence&
  operator=(const CoDatagramSocketReceiveSequence& recvmsg) noexcept {
    if (this != &recvmsg) {
      io_sock_dgram_recvmsg::operator=(recvmsg);
      Coroutine::operator=(recvmsg);
      buf_ = recvmsg.buf_;
      buf = buf_.buf();
    }
    return *this;
  }

  virtual ~CoDatagramSocketReceiveSequence() = default;

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
   * @param result the number of bytes received on success, or -1 on error (or
   *               if the operation is canceled).
   * @param flags  the flags set by the receive operation (may be
   *               #MessageFlags::EOR and #MessageFlags::TRUNC).
   * @param ec     the error code, or 0 on success.
   */
  virtual void operator()(ssize_t result, MessageFlag flags,
                          ::std::error_code ec) noexcept = 0;

 private:
  detail::BufferArray buf_;
};

/**
 * A datagram socket receive operation with a stackless coroutine as the
 * completion task.
 */
class CoDatagramSocketReceive : public io_sock_dgram_recvfrom,
                                public util::Coroutine {
 public:
  /// Constructs a receive operation.
  CoDatagramSocketReceive(const Buffer& buffer, MessageFlag flags,
                          io_endp* endp = nullptr,
                          ev_exec_t* exec = nullptr) noexcept
      : io_sock_dgram_recvfrom IO_SOCK_DGRAM_RECVFROM_INIT(
            this, buffer.data(), buffer.size(), static_cast<int>(flags), endp,
            exec, [](ev_task * task) noexcept {
              auto recvfrom = io_sock_dgram_recvfrom_from_task(task);
              ::std::error_code ec;
              auto result = recvfrom->recvmsg.r.result;
              auto flags = static_cast<MessageFlag>(recvfrom->recvmsg.flags);
              if (result == -1)
                ec = util::make_error_code(recvfrom->recvmsg.r.errc);
              auto self = static_cast<CoDatagramSocketReceive*>(recvfrom);
              (*self)(result, flags, ec);
            }) {}

  virtual ~CoDatagramSocketReceive() = default;

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
   * @param result the number of bytes received on success, or -1 on error (or
   *               if the operation is canceled).
   * @param flags  the flags set by the receive operation (may be
   *               #MessageFlags::EOR and #MessageFlags::TRUNC).
   * @param ec     the error code, or 0 on success.
   */
  virtual void operator()(ssize_t result, MessageFlag flags,
                          ::std::error_code ec) noexcept = 0;
};

/**
 * A vectored datagram socket send operation with a stackless coroutine as the
 * completion task.
 */
class CoDatagramSocketSendSequence : public io_sock_dgram_sendmsg,
                                     public util::Coroutine {
 public:
  /// Constructs a vectored send operation.
  template <class ConstBufferSequence>
  CoDatagramSocketSendSequence(const ConstBufferSequence& buffers,
                               MessageFlag flags, const io_endp* endp = nullptr,
                               ev_exec_t* exec = nullptr) noexcept
      : io_sock_dgram_sendmsg IO_SOCK_DGRAM_SENDMSG_INIT(
            nullptr, 0, static_cast<int>(flags), endp, exec,
            [](struct ev_task * task) noexcept {
              auto sendmsg = io_sock_dgram_sendmsg_from_task(task);
              auto result = sendmsg->r.result;
              ::std::error_code ec;
              if (result == -1) ec = util::make_error_code(sendmsg->r.errc);
              auto self = static_cast<CoDatagramSocketSendSequence*>(sendmsg);
              (*self)(result, ec);
            }),
        buf_(buffers) {
    buf = buf_.buf();
    bufcnt = buf_.bufcnt();
  }

  CoDatagramSocketSendSequence(
      const CoDatagramSocketSendSequence& sendmsg) noexcept
      : io_sock_dgram_sendmsg(sendmsg), Coroutine(sendmsg), buf_(sendmsg.buf_) {
    buf = buf_.buf();
  }

  CoDatagramSocketSendSequence&
  operator=(const CoDatagramSocketSendSequence& sendmsg) noexcept {
    if (this != &sendmsg) {
      io_sock_dgram_sendmsg::operator=(sendmsg);
      Coroutine::operator=(sendmsg);
      buf_ = sendmsg.buf_;
      buf = buf_.buf();
    }
    return *this;
  }

  virtual ~CoDatagramSocketSendSequence() = default;

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
 * A datagram socket send operation with a stackless coroutine as the completion
 * task.
 */
class CoDatagramSocketSend : public io_sock_dgram_sendto,
                             public util::Coroutine {
 public:
  /// Constructs a send operation.
  CoDatagramSocketSend(const ConstBuffer& buffer, MessageFlag flags,
                       const io_endp* endp = nullptr,
                       ev_exec_t* exec = nullptr) noexcept
      : io_sock_dgram_sendto IO_SOCK_DGRAM_SENDTO_INIT(
            this, buffer.data(), buffer.size(), static_cast<int>(flags), endp,
            exec, [](ev_task * task) noexcept {
              auto sendto = io_sock_dgram_sendto_from_task(task);
              ::std::error_code ec;
              auto result = sendto->sendmsg.r.result;
              if (result == -1)
                ec = util::make_error_code(sendto->sendmsg.r.errc);
              auto self = static_cast<CoDatagramSocketSend*>(sendto);
              (*self)(result, ec);
            }) {}

  virtual ~CoDatagramSocketSend() = default;

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

#endif  // !LELY_IO2_CO_SOCK_DGRAM_HPP_
