/**@file
 * This header file is part of the I/O library; it contains the base class for
 * I/O stream read and write operations with a stackless coroutine as the
 * completion task.
 *
 * @see lely/util/coroutine.hpp, lely/io2/stream.hpp
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

#ifndef LELY_IO2_CO_STREAM_HPP_
#define LELY_IO2_CO_STREAM_HPP_

#include <lely/io2/stream.hpp>
#include <lely/util/coroutine.hpp>

namespace lely {
namespace io {

/**
 * A vectored I/O stream read operation with a stackless coroutine as the
 * completion task.
 */
class CoStreamReadSequence : public io_stream_readv, public util::Coroutine {
 public:
  /// Constructs a vectored read operation.
  template <class BufferSequence>
  CoStreamReadSequence(BufferSequence& buffers,
                       ev_exec_t* exec = nullptr) noexcept
      : io_stream_readv IO_STREAM_READV_INIT(
            nullptr, 0, exec,
            [](struct ev_task * task) noexcept {
              auto readv = io_stream_readv_from_task(task);
              auto result = readv->r.result;
              ::std::error_code ec;
              if (result == -1) ec = util::make_error_code(readv->r.errc);
              auto self = static_cast<CoStreamReadSequence*>(readv);
              (*self)(result, ec);
            }),
        buf_(buffers) {
    buf = buf_.buf();
    bufcnt = buf_.bufcnt();
  }

  CoStreamReadSequence(const CoStreamReadSequence& readv) noexcept
      : io_stream_readv(readv), Coroutine(readv), buf_(readv.buf_) {
    buf = buf_.buf();
  }

  CoStreamReadSequence&
  operator=(const CoStreamReadSequence& readv) noexcept {
    if (this != &readv) {
      io_stream_readv::operator=(readv);
      Coroutine::operator=(readv);
      buf_ = readv.buf_;
      buf = buf_.buf();
    }
    return *this;
  }

  virtual ~CoStreamReadSequence() = default;

  operator ev_task&() & noexcept { return task; }

  /// Returns the executor to which the completion task is (to be) submitted.
  ev::Executor
  get_executor() const noexcept {
    return ev::Executor(task.exec);
  }

  /**
   * The coroutine to be executed once the read operation completes (or is
   * canceled).
   *
   * @param result the number of bytes read on success, 0 on end-of-file, or -1
   *               on error (or if the operation is canceled).
   * @param ec     the error code, or 0 on success.
   */
  virtual void operator()(ssize_t result, ::std::error_code ec) noexcept = 0;

 private:
  detail::BufferArray buf_;
};

/**
 * An I/O stream read operation with a stackless coroutine as the completion
 * task.
 */
class CoStreamRead : public io_stream_read, public util::Coroutine {
 public:
  using Signature = void(ssize_t, ::std::error_code);

  /// Constructs a read operation.
  CoStreamRead(const Buffer& buffer, ev_exec_t* exec = nullptr) noexcept
      : io_stream_read
        IO_STREAM_READ_INIT(this, buffer.data(), buffer.size(),
                            exec, [](ev_task * task) noexcept {
                              auto read = io_stream_read_from_task(task);
                              ::std::error_code ec;
                              auto result = read->readv.r.result;
                              if (result == -1)
                                ec = util::make_error_code(read->readv.r.errc);
                              auto self = static_cast<CoStreamRead*>(read);
                              (*self)(result, ec);
                            }) {}

  virtual ~CoStreamRead() = default;

  operator ev_task&() & noexcept { return readv.task; }

  /// Returns the executor to which the completion task is (to be) submitted.
  ev::Executor
  get_executor() const noexcept {
    return ev::Executor(readv.task.exec);
  }

  /**
   * The coroutine to be executed once the read operation completes (or is
   * canceled).
   *
   * @param result the number of bytes read on success, 0 on end-of-file, or -1
   *               on error (or if the operation is canceled).
   * @param ec     the error code, or 0 on success.
   */
  virtual void operator()(ssize_t result, ::std::error_code ec) noexcept = 0;
};

/**
 * A vectored I/O stream write operation with a stackless coroutine as the
 * completion task.
 */
class CoStreamWriteSequence : public io_stream_writev, public util::Coroutine {
 public:
  /// Constructs a vectored write operation.
  template <class ConstBufferSequence>
  CoStreamWriteSequence(const ConstBufferSequence& buffers,
                        ev_exec_t* exec = nullptr) noexcept
      : io_stream_writev IO_STREAM_WRITEV_INIT(
            nullptr, 0, exec,
            [](struct ev_task * task) noexcept {
              auto writev = io_stream_writev_from_task(task);
              auto result = writev->r.result;
              ::std::error_code ec;
              if (result == -1) ec = util::make_error_code(writev->r.errc);
              auto self = static_cast<CoStreamWriteSequence*>(writev);
              (*self)(result, ec);
            }),
        buf_(buffers) {
    buf = buf_.buf();
    bufcnt = buf_.bufcnt();
  }

  CoStreamWriteSequence(const CoStreamWriteSequence& writev) noexcept
      : io_stream_writev(writev), Coroutine(writev), buf_(writev.buf_) {
    buf = buf_.buf();
  }

  CoStreamWriteSequence&
  operator=(const CoStreamWriteSequence& writev) noexcept {
    if (this != &writev) {
      io_stream_writev::operator=(writev);
      Coroutine::operator=(writev);
      buf_ = writev.buf_;
      buf = buf_.buf();
    }
    return *this;
  }

  virtual ~CoStreamWriteSequence() = default;

  operator ev_task&() & noexcept { return task; }

  /// Returns the executor to which the completion task is (to be) submitted.
  ev::Executor
  get_executor() const noexcept {
    return ev::Executor(task.exec);
  }

  /**
   * The coroutine to be executed once the write operation completes (or is
   * canceled).
   *
   * @param result the number of bytes written on success, 0 on end-of-file, or
   *               -1 on error (or if the operation is canceled).
   * @param ec     the error code, or 0 on success.
   */
  virtual void operator()(ssize_t result, ::std::error_code ec) noexcept = 0;

 private:
  detail::ConstBufferArray buf_;
};

/**
 * An I/O stream write operation with a stackless coroutine as the completion
 * task.
 */
class CoStreamWrite : public io_stream_write, public util::Coroutine {
 public:
  using Signature = void(ssize_t, ::std::error_code);

  /// Constructs a write operation.
  CoStreamWrite(const ConstBuffer& buffer, ev_exec_t* exec = nullptr) noexcept
      : io_stream_write IO_STREAM_WRITE_INIT(
            this, buffer.data(), buffer.size(),
            exec, [](ev_task * task) noexcept {
              auto write = io_stream_write_from_task(task);
              ::std::error_code ec;
              auto result = write->writev.r.result;
              if (result == -1)
                ec = util::make_error_code(write->writev.r.errc);
              auto self = static_cast<CoStreamWrite*>(write);
              (*self)(result, ec);
            }) {}

  virtual ~CoStreamWrite() = default;

  operator ev_task&() & noexcept { return writev.task; }

  /// Returns the executor to which the completion task is (to be) submitted.
  ev::Executor
  get_executor() const noexcept {
    return ev::Executor(writev.task.exec);
  }

  /**
   * The coroutine to be executed once the write operation completes (or is
   * canceled).
   *
   * @param result the number of bytes written on success, 0 on end-of-file, or
   *               -1 on error (or if the operation is canceled).
   * @param ec     the error code, or 0 on success.
   */
  virtual void operator()(ssize_t result, ::std::error_code ec) noexcept = 0;
};

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_CO_STREAM_HPP_
