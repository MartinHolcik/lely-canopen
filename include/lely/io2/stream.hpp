/**@file
 * This header file is part of the I/O library; it contains the C++ interface
 * for the abstract I/O stream.
 *
 * @see lely/io2/stream.h
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

#ifndef LELY_IO2_STREAM_HPP_
#define LELY_IO2_STREAM_HPP_

#include <lely/ev/future.hpp>
#include <lely/io2/buf.hpp>
#include <lely/io2/dev.hpp>
#include <lely/io2/stream.h>

#include <utility>

namespace lely {
namespace io {

namespace detail {

template <class F>
class StreamReadSequenceWrapper : public io_stream_readv {
 public:
  template <class BufferSequence>
  StreamReadSequenceWrapper(BufferSequence& buffers, ev_exec_t* exec, F&& f)
      : io_stream_readv IO_STREAM_READV_INIT(
            nullptr, 0, exec,
            [](struct ev_task * task) noexcept {
              auto readv = io_stream_readv_from_task(task);
              auto result = readv->r.result;
              ::std::error_code ec;
              if (result == -1) ec = util::make_error_code(readv->r.errc);
              auto self = static_cast<StreamReadSequenceWrapper*>(readv);
              compat::invoke(::std::move(self->func_), result, ec);
              delete self;
            }),
        buf_(buffers),
        func_(::std::forward<F>(f)) {
    buf = buf_.buf();
    bufcnt = buf_.bufcnt();
  }

  StreamReadSequenceWrapper(const StreamReadSequenceWrapper&) = delete;

  StreamReadSequenceWrapper& operator=(const StreamReadSequenceWrapper&) =
      delete;

  operator ev_task&() & noexcept { return task; }

 private:
  detail::BufferArray buf_;
  typename ::std::decay<F>::type func_;
};

}  // namespace detail

/**
 * Creates a vectored I/O stream read operation with a completion task. The
 * operation deletes itself after it is completed, so it MUST NOT be deleted
 * once it is submitted to an I/O stream.
 */
template <class BufferSequence, class F>
inline typename ::std::enable_if<
    compat::is_invocable<F, ssize_t, ::std::error_code>::value,
    detail::StreamReadSequenceWrapper<F>*>::type
make_stream_read_sequence_wrapper(BufferSequence& buffers, ev_exec_t* exec,
                                  F&& f) {
  return new detail::StreamReadSequenceWrapper<F>(buffers, exec,
                                                  ::std::forward<F>(f));
}

/**
 * A vectored read operation suitable for use with an I/O stream. This class
 * stores a callable object with signature
 * `void(ssize_t result, std::error_code ec)`, which is invoked upon completion
 * (or cancellation) of the read operation.
 */
class StreamReadSequence : public io_stream_readv {
 public:
  using Signature = void(ssize_t, ::std::error_code);

  /// Constructs a vectored read operation with a completion task.
  template <class BufferSequence, class F>
  StreamReadSequence(BufferSequence& buffers, ev_exec_t* exec, F&& f)
      : io_stream_readv IO_STREAM_READV_INIT(
            nullptr, 0, exec,
            [](struct ev_task * task) noexcept {
              auto readv = io_stream_readv_from_task(task);
              auto self = static_cast<StreamReadSequence*>(readv);
              if (self->func_) {
                auto result = readv->r.result;
                ::std::error_code ec;
                if (result == -1) ec = util::make_error_code(readv->r.errc);
                self->func_(result, ec);
              }
            }),
        buf_(buffers),
        func_(::std::forward<F>(f)) {
    buf = buf_.buf();
    bufcnt = buf_.bufcnt();
  }

  /// Constructs a vectored read operation with a completion task.
  template <class BufferSequence, class F>
  StreamReadSequence(BufferSequence& buffers, F&& f)
      : StreamReadSequence(buffers, nullptr, ::std::forward<F>(f)) {}

  StreamReadSequence(const StreamReadSequence&) = delete;

  StreamReadSequence& operator=(const StreamReadSequence&) = delete;

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
class StreamReadWrapper : public io_stream_read {
 public:
  StreamReadWrapper(const Buffer& buffer, ev_exec_t* exec, F&& f)
      : io_stream_read IO_STREAM_READ_INIT(
            this, buffer.data(), buffer.size(), exec,
            [](ev_task * task) noexcept {
              auto read = io_stream_read_from_task(task);
              auto result = read->readv.r.result;
              ::std::error_code ec;
              if (result == -1) ec = util::make_error_code(read->readv.r.errc);
              auto self = static_cast<StreamReadWrapper*>(read);
              compat::invoke(::std::move(self->func_), result, ec);
              delete self;
            }),
        func_(::std::forward<F>(f)) {}

  StreamReadWrapper(const StreamReadWrapper&) = delete;

  StreamReadWrapper& operator=(const StreamReadWrapper&) = delete;

  operator ev_task&() & noexcept { return readv.task; }

 private:
  typename ::std::decay<F>::type func_;
};

}  // namespace detail

/**
 * Creates an I/O stream read operation with a completion task. The operation
 * deletes itself after it is completed, so it MUST NOT be deleted once it is
 * submitted to an I/O stream.
 */
template <class F>
inline typename ::std::enable_if<
    compat::is_invocable<F, ssize_t, ::std::error_code>::value,
    detail::StreamReadWrapper<F>*>::type
make_stream_read_wrapper(const Buffer& buffer, ev_exec_t* exec, F&& f) {
  return new detail::StreamReadWrapper<F>(buffer, exec, ::std::forward<F>(f));
}

/**
 * A read operation suitable for use with an I/O stream. This class stores a
 * callable object with signature `void(ssize_t result, std::error_code ec)`,
 * which is invoked upon completion (or cancellation) of the read operation.
 */
class StreamRead : public io_stream_read {
 public:
  using Signature = void(ssize_t, ::std::error_code);

  /// Constructs a read operation with a completion task.
  template <class F>
  StreamRead(const Buffer& buffer, ev_exec_t* exec, F&& f)
      : io_stream_read IO_STREAM_READ_INIT(
            this, buffer.data(), buffer.size(), exec,
            [](ev_task * task) noexcept {
              auto read = io_stream_read_from_task(task);
              auto self = static_cast<StreamRead*>(read);
              if (self->func_) {
                auto result = read->readv.r.result;
                ::std::error_code ec;
                if (result == -1)
                  ec = util::make_error_code(read->readv.r.errc);
                self->func_(result, ec);
              }
            }),
        func_(::std::forward<F>(f)) {}

  /// Constructs a read operation with a completion task.
  template <class F>
  StreamRead(const Buffer& buffer, F&& f)
      : StreamRead(buffer, nullptr, ::std::forward<F>(f)) {}

  StreamRead(const StreamRead&) = delete;

  StreamRead& operator=(const StreamRead&) = delete;

  operator ev_task&() & noexcept { return readv.task; }

  /// Returns the executor to which the completion task is (to be) submitted.
  ev::Executor
  get_executor() const noexcept {
    return ev::Executor(readv.task.exec);
  }

 private:
  ::std::function<Signature> func_;
};

namespace detail {

template <class F>
class StreamWriteSequenceWrapper : public io_stream_writev {
 public:
  template <class ConstBufferSequence>
  StreamWriteSequenceWrapper(const ConstBufferSequence& buffers,
                             ev_exec_t* exec, F&& f)
      : io_stream_writev IO_STREAM_WRITEV_INIT(
            nullptr, 0, exec,
            [](struct ev_task * task) noexcept {
              auto writev = io_stream_writev_from_task(task);
              auto result = writev->r.result;
              ::std::error_code ec;
              if (result == -1) ec = util::make_error_code(writev->r.errc);
              auto self = static_cast<StreamWriteSequenceWrapper*>(writev);
              compat::invoke(::std::move(self->func_), result, ec);
              delete self;
            }),
        buf_(buffers),
        func_(::std::forward<F>(f)) {
    buf = buf_.buf();
    bufcnt = buf_.bufcnt();
  }

  StreamWriteSequenceWrapper(const StreamWriteSequenceWrapper&) = delete;

  StreamWriteSequenceWrapper& operator=(const StreamWriteSequenceWrapper&) =
      delete;

  operator ev_task&() & noexcept { return task; }

 private:
  detail::ConstBufferArray buf_;
  typename ::std::decay<F>::type func_;
};

}  // namespace detail

/**
 * Creates a vectored I/O stream write operation with a completion task. The
 * operation deletes itself after it is completed, so it MUST NOT be deleted
 * once it is submitted to an I/O stream.
 */
template <class ConstBufferSequence, class F>
inline typename ::std::enable_if<
    compat::is_invocable<F, ssize_t, ::std::error_code>::value,
    detail::StreamWriteSequenceWrapper<F>*>::type
make_stream_write_sequence_wrapper(const ConstBufferSequence& buffers,
                                   ev_exec_t* exec, F&& f) {
  return new detail::StreamWriteSequenceWrapper<F>(buffers, exec,
                                                   ::std::forward<F>(f));
}

/**
 * A vectored write operation suitable for use with an I/O stream. This class
 * stores a callable object with signature
 * `void(ssize_t result, std::error_code ec)`, which is invoked upon completion
 * (or cancellation) of the write operation.
 */
class StreamWriteSequence : public io_stream_writev {
 public:
  using Signature = void(ssize_t, ::std::error_code);

  /// Constructs a vectored write operation with a completion task.
  template <class ConstBufferSequence, class F>
  StreamWriteSequence(const ConstBufferSequence& buffers, ev_exec_t* exec,
                      F&& f)
      : io_stream_writev IO_STREAM_WRITEV_INIT(
            nullptr, 0, exec,
            [](struct ev_task * task) noexcept {
              auto writev = io_stream_writev_from_task(task);
              auto self = static_cast<StreamWriteSequence*>(writev);
              if (self->func_) {
                auto result = writev->r.result;
                ::std::error_code ec;
                if (result == -1) ec = util::make_error_code(writev->r.errc);
                self->func_(result, ec);
              }
            }),
        buf_(buffers),
        func_(::std::forward<F>(f)) {
    buf = buf_.buf();
    bufcnt = buf_.bufcnt();
  }

  /// Constructs a vectored write operation with a completion task.
  template <class ConstBufferSequence, class F>
  StreamWriteSequence(const ConstBufferSequence& buffers, F&& f)
      : StreamWriteSequence(buffers, nullptr, ::std::forward<F>(f)) {}

  StreamWriteSequence(const StreamWriteSequence&) = delete;

  StreamWriteSequence& operator=(const StreamWriteSequence&) = delete;

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
class StreamWriteWrapper : public io_stream_write {
 public:
  StreamWriteWrapper(const ConstBuffer& buffer, ev_exec_t* exec, F&& f)
      : io_stream_write IO_STREAM_WRITE_INIT(
            this, buffer.data(), buffer.size(), exec,
            [](ev_task * task) noexcept {
              auto write = io_stream_write_from_task(task);
              auto result = write->writev.r.result;
              ::std::error_code ec;
              if (result == -1)
                ec = util::make_error_code(write->writev.r.errc);
              auto self = static_cast<StreamWriteWrapper*>(write);
              compat::invoke(::std::move(self->func_), result, ec);
              delete self;
            }),
        func_(::std::forward<F>(f)) {}

  StreamWriteWrapper(const StreamWriteWrapper&) = delete;

  StreamWriteWrapper& operator=(const StreamWriteWrapper&) = delete;

  operator ev_task&() & noexcept { return writev.task; }

 private:
  typename ::std::decay<F>::type func_;
};

}  // namespace detail

/**
 * Creates an I/O stream write operation with a completion task. The operation
 * deletes itself after it is completed, so it MUST NOT be deleted once it is
 * submitted to an I/O stream.
 */
template <class F>
inline typename ::std::enable_if<
    compat::is_invocable<F, ssize_t, ::std::error_code>::value,
    detail::StreamWriteWrapper<F>*>::type
make_stream_write_wrapper(const ConstBuffer& buffer, ev_exec_t* exec, F&& f) {
  return new detail::StreamWriteWrapper<F>(buffer, exec, ::std::forward<F>(f));
}

/**
 * A write operation suitable for use with an I/O stream. This class stores a
 * callable object with signature `void(ssize_t result, std::error_code ec)`,
 * which is invoked upon completion (or cancellation) of the write operation.
 */
class StreamWrite : public io_stream_write {
 public:
  using Signature = void(ssize_t, ::std::error_code);

  /// Constructs a write operation with a completion task.
  template <class F>
  StreamWrite(const ConstBuffer& buffer, ev_exec_t* exec, F&& f)
      : io_stream_write IO_STREAM_WRITE_INIT(
            this, buffer.data(), buffer.size(), exec,
            [](ev_task * task) noexcept {
              auto write = io_stream_write_from_task(task);
              auto self = static_cast<StreamWrite*>(write);
              if (self->func_) {
                auto result = write->writev.r.result;
                ::std::error_code ec;
                if (result == -1)
                  ec = util::make_error_code(write->writev.r.errc);
                self->func_(result, ec);
              }
            }),
        func_(::std::forward<F>(f)) {}

  /// Constructs a write operation with a completion task.
  template <class F>
  StreamWrite(const ConstBuffer& buffer, F&& f)
      : StreamWrite(buffer, nullptr, ::std::forward<F>(f)) {}

  StreamWrite(const StreamWrite&) = delete;

  StreamWrite& operator=(const StreamWrite&) = delete;

  operator ev_task&() & noexcept { return writev.task; }

  /// Returns the executor to which the completion task is (to be) submitted.
  ev::Executor
  get_executor() const noexcept {
    return ev::Executor(writev.task.exec);
  }

 private:
  ::std::function<Signature> func_;
};

/**
 * A reference to an abstract I/O stream. This class is a wrapper around
 * `#io_stream_t*`.
 */
class StreamBase : public virtual Device {
 public:
  using Device::operator io_dev_t*;

  explicit StreamBase(io_stream_t* stream_) noexcept
      : Device(nullptr), stream(stream_) {}

  operator io_stream_t*() const noexcept { return stream; }

  /// @see io_stream_readv()
  template <class BufferSequence>
  ssize_t
  read(BufferSequence& buffers, ::std::error_code& ec) {
    detail::BufferArray buf(buffers);
    if (ec) return -1;
    int errsv = get_errc();
    set_errc(0);
    ssize_t result = io_stream_readv(*this, buf.buf(), buf.bufcnt());
    if (result < 0) ec = util::make_error_code();
    set_errc(errsv);
    return result;
  }

  /// @see io_stream_readv()
  template <class BufferSequence>
  size_t
  read(BufferSequence& buffers) {
    ::std::error_code ec;
    ssize_t result = read(buffers, ec);
    if (result < 0) throw ::std::system_error(ec, "read");
    return result;
  }

  /// @see io_stream_submit_readv()
  void
  submit_read(struct io_stream_readv& readv) noexcept {
    io_stream_submit_readv(*this, &readv);
  }

  /// @see io_stream_submit_readv()
  template <class BufferSequence, class F>
  void
  submit_read(BufferSequence& buffers, ev_exec_t* exec, F&& f) {
    submit_read(*make_stream_read_sequence_wrapper(buffers, exec,
                                                   ::std::forward<F>(f)));
  }

  /// @see io_stream_submit_readv()
  template <class BufferSequence, class F>
  void
  submit_read(BufferSequence& buffers, F&& f) {
    submit_read(buffers, nullptr, ::std::forward<F>(f));
  }

  /// @see io_stream_cancel_readv()
  bool
  cancel_read(struct io_stream_readv& readv) noexcept {
    return io_stream_cancel_readv(*this, &readv) != 0;
  }

  /// @see io_stream_abort_readv()
  bool
  abort_read(struct io_stream_readv& readv) noexcept {
    return io_stream_abort_readv(*this, &readv) != 0;
  }

  /// @see io_stream_async_readv()
  template <class BufferSequence>
  ev::Future<ssize_t, int>
  async_read(ev_exec_t* exec, BufferSequence& buffers,
             struct io_stream_readv** preadv = nullptr) {
    detail::BufferArray buf(buffers);
    auto future =
        io_stream_async_readv(*this, exec, buf.buf(), buf.bufcnt(), preadv);
    if (!future) util::throw_errc("async_read");
    return ev::Future<ssize_t, int>(future);
  }

  /// @see io_stream_async_readv()
  template <class BufferSequence>
  ev::Future<ssize_t, int>
  async_read(BufferSequence& buffers,
             struct io_stream_readv** preadv = nullptr) {
    return async_read(nullptr, buffers, preadv);
  }

  /// @see io_stream_read()
  ssize_t
  read(const Buffer& buffer, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    ssize_t result =
        io_stream_read(*this, buffer.data(), buffer.size());
    if (result >= 0)
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
    return result;
  }

  /// @see io_stream_read()
  size_t
  read(const Buffer& buffer) {
    ::std::error_code ec;
    ssize_t result = read(buffer, ec);
    if (result < 0) throw ::std::system_error(ec, "read");
    return result;
  }

  /// @see io_stream_submit_read()
  void
  submit_read(struct io_stream_read& read) noexcept {
    io_stream_submit_read(*this, &read);
  }

  /// @see io_stream_submit_read()
  template <class F>
  void
  submit_read(const Buffer& buffer, ev_exec_t* exec, F&& f) {
    submit_read(*make_stream_read_wrapper(buffer, exec, ::std::forward<F>(f)));
  }

  /// @see io_stream_submit_read()
  template <class F>
  void
  submit_read(const Buffer& buffer, F&& f) {
    submit_read(buffer, nullptr, ::std::forward<F>(f));
  }

  /// @see io_stream_cancel_read()
  bool
  cancel_read(struct io_stream_read& read) noexcept {
    return io_stream_cancel_read(*this, &read) != 0;
  }

  /// @see io_stream_abort_read()
  bool
  abort_read(struct io_stream_read& read) noexcept {
    return io_stream_abort_read(*this, &read) != 0;
  }

  /// @see io_stream_async_read()
  ev::Future<ssize_t, int>
  async_read(ev_exec_t* exec, const Buffer& buffer,
             struct io_stream_read** pread = nullptr) {
    auto future =
        io_stream_async_read(*this, exec, buffer.data(), buffer.size(), pread);
    if (!future) util::throw_errc("async_read");
    return ev::Future<ssize_t, int>(future);
  }

  /// @see io_stream_async_read()
  ev::Future<ssize_t, int>
  async_read(const Buffer& buffer, struct io_stream_read** pread = nullptr) {
    return async_read(nullptr, buffer, pread);
  }

  /// @see io_stream_writev()
  template <class ConstBufferSequence>
  ssize_t
  write(const ConstBufferSequence& buffers, ::std::error_code& ec) {
    detail::ConstBufferArray buf(buffers);
    if (ec) return -1;
    int errsv = get_errc();
    set_errc(0);
    ssize_t result = io_stream_writev(*this, buf.buf(), buf.bufcnt());
    if (result < 0) ec = util::make_error_code();
    set_errc(errsv);
    return result;
  }

  /// @see io_stream_writev()
  template <class ConstBufferSequence>
  ssize_t
  write(const ConstBufferSequence& buffers) {
    ::std::error_code ec;
    ssize_t result = write(buffers, ec);
    if (result < 0) throw ::std::system_error(ec, "write");
    return result;
  }

  /// @see io_stream_submit_writev()
  void
  submit_write(struct io_stream_writev& writev) noexcept {
    io_stream_submit_writev(*this, &writev);
  }

  /// @see io_stream_submit_writev()
  template <class ConstBufferSequence, class F>
  void
  submit_write(const ConstBufferSequence& buffers, ev_exec_t* exec, F&& f) {
    submit_write(*make_stream_write_sequence_wrapper(buffers, exec,
                                                     ::std::forward<F>(f)));
  }

  /// @see io_stream_submit_writev()
  template <class ConstBufferSequence, class F>
  void
  submit_write(const ConstBufferSequence& buffers, F&& f) {
    submit_write(buffers, nullptr, ::std::forward<F>(f));
  }

  /// @see io_stream_cancel_writev()
  bool
  cancel_write(struct io_stream_writev& writev) noexcept {
    return io_stream_cancel_writev(*this, &writev) != 0;
  }

  /// @see io_stream_abort_writev()
  bool
  abort_write(struct io_stream_writev& writev) noexcept {
    return io_stream_abort_writev(*this, &writev) != 0;
  }

  /// @see io_stream_async_writev()
  template <class ConstBufferSequence>
  ev::Future<ssize_t, int>
  async_write(ev_exec_t* exec, const ConstBufferSequence& buffers,
              struct io_stream_writev** pwritev = nullptr) {
    detail::ConstBufferArray buf(buffers);
    auto future =
        io_stream_async_writev(*this, exec, buf.buf(), buf.bufcnt(), pwritev);
    if (!future) util::throw_errc("async_write");
    return ev::Future<ssize_t, int>(future);
  }

  /// @see io_stream_async_writev()
  template <class ConstBufferSequence>
  ev::Future<ssize_t, int>
  async_write(const ConstBufferSequence& buffers,
              struct io_stream_writev** pwritev = nullptr) {
    return async_writev(nullptr, buffers, pwritev);
  }

  /// @see io_stream_write()
  ssize_t
  write(const ConstBuffer& buffer, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    ssize_t result =
        io_stream_write(*this, buffer.data(), buffer.size());
    if (result >= 0)
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
    return result;
  }

  /// @see io_stream_write()
  size_t
  write(const ConstBuffer& buffer) {
    ::std::error_code ec;
    ssize_t result = write(buffer, ec);
    if (result < 0) throw ::std::system_error(ec, "write");
    return result;
  }

  /// @see io_stream_submit_write()
  void
  submit_write(struct io_stream_write& write) noexcept {
    io_stream_submit_write(*this, &write);
  }

  /// @see io_stream_submit_write()
  template <class F>
  void
  submit_write(const ConstBuffer& buffer, ev_exec_t* exec, F&& f) {
    submit_write(
        *make_stream_write_wrapper(buffer, exec, ::std::forward<F>(f)));
  }

  /// @see io_stream_submit_write()
  template <class F>
  void
  submit_write(const ConstBuffer& buffer, F&& f) {
    return submit_write(buffer, nullptr, ::std::forward<F>(f));
  }

  /// @see io_stream_cancel_write()
  bool
  cancel_write(struct io_stream_write& write) noexcept {
    return io_stream_cancel_write(*this, &write) != 0;
  }

  /// @see io_stream_abort_write()
  bool
  abort_write(struct io_stream_write& write) noexcept {
    return io_stream_abort_write(*this, &write) != 0;
  }

  /// @see io_stream_async_write()
  ev::Future<ssize_t, int>
  async_write(ev_exec_t* exec, const ConstBuffer& buffer,
              struct io_stream_write** pwrite = nullptr) {
    auto future = io_stream_async_write(*this, exec, buffer.data(),
                                        buffer.size(), pwrite);
    if (!future) util::throw_errc("async_write");
    return ev::Future<ssize_t, int>(future);
  }

  /// @see io_stream_async_write()
  ev::Future<ssize_t, int>
  async_write(const ConstBuffer& buffer,
              struct io_stream_write** pwrite = nullptr) {
    return async_write(nullptr, buffer, pwrite);
  }

 protected:
  io_stream_t* stream{nullptr};
};

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_STREAM_HPP_
