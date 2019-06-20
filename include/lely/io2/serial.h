/**@file
 * This header file is part of the I/O library; it contains the abstract serial
 * port interface.
 *
 * @copyright 2016-2019 Lely Industries N.V.
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

#ifndef LELY_IO2_SERIAL_H_
#define LELY_IO2_SERIAL_H_

#include <lely/io2/stream.h>

#ifndef LELY_IO_SERIAL_INLINE
#define LELY_IO_SERIAL_INLINE static inline
#endif

/// The serial port buffer to purge.
enum io_serial_purge {
	/// Purge data received but not read.
	IO_SERIAL_PURGE_RX = 1u << 0,
	/// Purge data written but not transmitted.
	IO_SERIAL_PURGE_TX = 1u << 1,
	/**
	 * Purge both data received but not read and data written but not
	 * transmitted.
	 */
	IO_SERIAL_PURGE_RXTX = IO_SERIAL_PURGE_RX | IO_SERIAL_PURGE_TX
};

/// The flow control used by a serial port.
enum io_serial_flow_ctrl {
	/// No flow control.
	IO_SERIAL_FLOW_CTRL_NONE,
	/// Software flow control.
	IO_SERIAL_FLOW_CTRL_SW,
	/// Hardware flow control.
	IO_SERIAL_FLOW_CTRL_HW
};

/// The serial port parity.
enum io_serial_parity {
	/// No parity.
	IO_SERIAL_PARITY_NONE,
	/// Odd parity.
	IO_SERIAL_PARITY_ODD,
	/// Even parity.
	IO_SERIAL_PARITY_EVEN
};

/// The number of stop bits used by a serial port.
enum io_serial_stop_bits {
	/// 1 stop bit.
	IO_SERIAL_STOP_BITS_ONE,
	/// 1.5 stop bits.
	IO_SERIAL_STOP_BITS_ONE_FIVE,
	/// 2 stop bits.
	IO_SERIAL_STOP_BITS_TWO
};

/// An abstract serial port.
typedef const struct io_serial_vtbl *const io_serial_t;

#ifdef __cplusplus
extern "C" {
#endif

struct io_serial_vtbl {
	io_stream_t *(*get_stream)(const io_serial_t *serial);
	int (*send_break)(io_serial_t *serial);
	int (*flush)(io_serial_t *serial);
	int (*purge)(io_serial_t *serial, int how);
	int (*get_baud_rate)(const io_serial_t *serial);
	int (*set_baud_rate)(io_serial_t *serial, int optval);
	int (*get_flow_ctrl)(const io_serial_t *serial);
	int (*set_flow_ctrl)(io_serial_t *serial, int optval);
	int (*get_parity)(const io_serial_t *serial);
	int (*set_parity)(io_serial_t *serial, int optval);
	int (*get_stop_bits)(const io_serial_t *serial);
	int (*set_stop_bits)(io_serial_t *serial, int optval);
	int (*get_char_size)(const io_serial_t *serial);
	int (*set_char_size)(io_serial_t *serial, int optval);
	int (*get_rx_timeout)(const io_serial_t *serial);
	int (*set_rx_timeout)(io_serial_t *serial, int optval);
	int (*get_tx_timeout)(const io_serial_t *serial);
	int (*set_tx_timeout)(io_serial_t *serial, int optval);
};

/// @see io_dev_get_ctx()
static inline io_ctx_t *io_serial_get_ctx(const io_serial_t *serial);

/// @see io_dev_get_exec()
static inline ev_exec_t *io_serial_get_exec(const io_serial_t *serial);

/// @see io_dev_cancel()
static inline size_t io_serial_cancel(
		io_serial_t *serial, struct ev_task *task);

/// @see io_dev_abort()
static inline size_t io_serial_abort(io_serial_t *serial, struct ev_task *task);

/// @see io_stream_get_dev()
static inline io_dev_t *io_serial_get_dev(const io_serial_t *serial);

/// @see io_stream_readv()
static inline ssize_t io_serial_readv(
		io_serial_t *serial, const struct io_buf *buf, int bufcnt);

/// @see io_stream_submit_readv()
static inline void io_serial_submit_readv(
		io_serial_t *serial, struct io_stream_readv *readv);

/// @see io_stream_cancel_readv()
static inline size_t io_serial_cancel_readv(
		io_serial_t *serial, struct io_stream_readv *readv);

/// @see io_stream_abort_readv()
static inline size_t io_serial_abort_readv(
		io_serial_t *serial, struct io_stream_readv *readv);

/// @see io_stream_async_readv()
static inline ev_future_t *io_serial_async_readv(io_serial_t *serial,
		ev_exec_t *exec, const struct io_buf *buf, int bufcnt,
		struct io_stream_readv **preadv);

/// @see io_stream_read()
static inline ssize_t io_serial_read(
		io_serial_t *serial, void *buf, size_t nbytes);

/// @see io_stream_submit_read()
static inline void io_serial_submit_read(
		io_serial_t *serial, struct io_stream_read *read);

/// @see io_stream_cancel_read()
static inline size_t io_serial_cancel_read(
		io_serial_t *serial, struct io_stream_read *read);

/// @see io_stream_abort_read()
static inline size_t io_serial_abort_read(
		io_serial_t *serial, struct io_stream_read *read);

/// @see io_stream_async_read()
static inline ev_future_t *io_serial_async_read(io_serial_t *serial,
		ev_exec_t *exec, void *buf, size_t nbytes,
		struct io_stream_read **pread);

/// @see io_stream_writev()
static inline ssize_t io_serial_writev(
		io_serial_t *serial, const struct io_buf *buf, int bufcnt);

/// @see io_stream_submit_writev()
static inline void io_serial_submit_writev(
		io_serial_t *serial, struct io_stream_writev *writev);

/// @see io_stream_cancel_writev()
static inline size_t io_serial_cancel_writev(
		io_serial_t *serial, struct io_stream_writev *writev);

/// @see io_stream_abort_writev()
static inline size_t io_serial_abort_writev(
		io_serial_t *serial, struct io_stream_writev *writev);

/// @see io_stream_async_writev()
static inline ev_future_t *io_serial_async_writev(io_serial_t *serial,
		ev_exec_t *exec, const struct io_buf *buf, int bufcnt,
		struct io_stream_writev **pwritev);

/// @see io_stream_write()
static inline ssize_t io_serial_write(
		io_serial_t *serial, const void *buf, size_t nbytes);

/// @see io_stream_submit_write()
static inline void io_serial_submit_write(
		io_serial_t *serial, struct io_stream_write *write);

/// @see io_stream_cancel_write()
static inline size_t io_serial_cancel_write(
		io_serial_t *serial, struct io_stream_write *write);

/// @see io_stream_abort_write()
static inline size_t io_serial_abort_write(
		io_serial_t *serial, struct io_stream_write *write);

/// @see io_stream_async_write()
static inline ev_future_t *io_serial_async_write(io_serial_t *serial,
		ev_exec_t *exec, const void *buf, size_t nbytes,
		struct io_stream_write **pwrite);

/// Returns a pointer to the abstract stream representing the serial port.
LELY_IO_SERIAL_INLINE io_stream_t *io_serial_get_stream(
		const io_serial_t *serial);

/**
 * Transmits a continuous stream of zeri-valued bits for at least 0.25 seconds
 * and not more than 0.5 seconds.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 */
LELY_IO_SERIAL_INLINE int io_serial_send_break(io_serial_t *serial);

/**
 * Blocks until all data written to a serial port is transmitted.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 */
LELY_IO_SERIAL_INLINE int io_serial_flush(io_serial_t *serial);

/**
 * Discards data written to a serial port but not transmitted, or data received
 * but not read, or both, depending on the value of <b>how</b>.
 *
 * @param serial a pointer to a serial port.
 * @param how    one of #IO_SERIAL_PURGE_RX, #IO_SERIAL_PURGE_TX or
 *               #IO_SERIAL_PURGE_RXTX.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 */
LELY_IO_SERIAL_INLINE int io_serial_purge(io_serial_t *serial, int how);

/**
 * Obtains the baud rate of a serial port.
 *
 * @see io_serial_set_baud_rate()
 */
LELY_IO_SERIAL_INLINE int io_serial_get_baud_rate(const io_serial_t *serial);

/**
 * Sets the baud rate of a serial port. The parameter change occurs immediately
 * (as if by POSIX `tcsetattr()` with parameter `TCSANOW`);
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_serial_get_baud_rate()
 */
LELY_IO_SERIAL_INLINE int io_serial_set_baud_rate(
		io_serial_t *serial, int optval);

/**
 * Obtains the flow control used by a serial port.
 *
 * @returns one of #IO_SERIAL_FLOW_CTRL_NONE, #IO_SERIAL_FLOW_CTRL_SW or
 * #IO_SERIAL_FLOW_CTRL_HW.
 *
 * @see io_serial_set_flow_ctrl()
 */
LELY_IO_SERIAL_INLINE int io_serial_get_flow_ctrl(const io_serial_t *serial);

/**
 * Sets the flow control used by a serial port. The parameter change occurs
 * immediately (as if by POSIX `tcsetattr()` with parameter `TCSANOW`);
 *
 * @param serial a pointer to a serial port.
 * @param optval one of #IO_SERIAL_FLOW_CTRL_NONE, #IO_SERIAL_FLOW_CTRL_SW or
 *               #IO_SERIAL_FLOW_CTRL_HW.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_serial_get_flow_ctrl()
 */
LELY_IO_SERIAL_INLINE int io_serial_set_flow_ctrl(
		io_serial_t *serial, int optval);

/**
 * Obtains the serial port parity.
 *
 * @returns one of #IO_SERIAL_PARITY_NONE, #IO_SERIAL_PARITY_ODD, or
 * #IO_SERIAL_PARITY_EVEN.
 *
 * @see io_serial_set_parity()
 */
LELY_IO_SERIAL_INLINE int io_serial_get_parity(const io_serial_t *serial);

/**
 * Sets the serial port parity. The parameter change occurs immediately (as if
 * by POSIX `tcsetattr()` with parameter `TCSANOW`);
 *
 * @param serial a pointer to a serial port.
 * @param optval one of #IO_SERIAL_PARITY_NONE, #IO_SERIAL_PARITY_ODD, or
 *               #IO_SERIAL_PARITY_EVEN.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_serial_get_parity()
 */
LELY_IO_SERIAL_INLINE int io_serial_set_parity(io_serial_t *serial, int optval);

/**
 * Obtains the number of stop bits used by a serial port.
 *
 * @returns one of #IO_SERIAL_STOP_BITS_ONE, #IO_SERIAL_STOP_BITS_ONE_FIVE, or
 * #IO_SERIAL_STOP_BITS_TWO.
 *
 * @see io_serial_set_stop_bits()
 */
LELY_IO_SERIAL_INLINE int io_serial_get_stop_bits(const io_serial_t *serial);

/**
 * Sets the number of stop bits used by a serial port. The parameter change
 * occurs immediately (as if by POSIX `tcsetattr()` with parameter `TCSANOW`);
 *
 * @param serial a pointer to a serial port.
 * @param optval #IO_SERIAL_STOP_BITS_ONE, #IO_SERIAL_STOP_BITS_ONE_FIVE, or
 *               #IO_SERIAL_STOP_BITS_TWO.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_serial_get_stop_bits()
 */
LELY_IO_SERIAL_INLINE int io_serial_set_stop_bits(
		io_serial_t *serial, int optval);

/**
 * Obtains the character size (in bits) of a serial port.
 *
 * @see io_serial_set_char_size()
 */
LELY_IO_SERIAL_INLINE int io_serial_get_char_size(const io_serial_t *serial);

/**
 * Sets the character size (in bits) of a serial port. The parameter change
 * occurs immediately (as if by POSIX `tcsetattr()` with parameter `TCSANOW`);
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_serial_get_char_size()
 */
LELY_IO_SERIAL_INLINE int io_serial_set_char_size(
		io_serial_t *serial, int optval);

/**
 * Obtains the read timeout of a serial port. For vectored read operations, the
 * timeout is multiplied by the number of buffers.
 *
 * @returns the timeout (in milliseconds), or -1 if read operations never time
 * out.
 *
 * @see io_serial_set_rx_timeout()
 */
LELY_IO_SERIAL_INLINE int io_serial_get_rx_timeout(const io_serial_t *serial);

/**
 * Sets the read timeout of a serial port. For vectored read operations, the
 * timeout is multiplied by the number of buffers.
 *
 * @param serial a pointer to a serial port.
 * @param optval the timeout (in milliseconds). If <b>optval</b> is negative,
 *               read operations never time out.
 *
 * The default timeout is -1 if the serial port is capable of asynchronous I/O,
 * and #LELY_IO_RX_TIMEOUT if not. Note that a non-negative timeout makes read
 * operations synchronous on POSIX platforms.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_serial_get_rx_timeout()
 */
LELY_IO_SERIAL_INLINE int io_serial_set_rx_timeout(
		io_serial_t *serial, int optval);

/**
 * Obtains the write timeout of a serial port. For vectored write operations,
 * the timeout is multiplied by the number of buffers.
 *
 * @returns the timeout (in milliseconds), or -1 if write operations never time
 * out.
 *
 * @see io_serial_set_tx_timeout()
 */
LELY_IO_SERIAL_INLINE int io_serial_get_tx_timeout(const io_serial_t *serial);

/**
 * Sets the write timeout of a serial port. For vectored write operations, the
 * timeout is multiplied by the number of buffers.
 *
 * @param serial a pointer to a serial port.
 * @param optval the timeout (in milliseconds). If <b>optval</b> is negative,
 *               write operations never time out.
 *
 * The default timeout is -1 if the serial port is capable of asynchronous I/O,
 * and #LELY_IO_TX_TIMEOUT if not. Note that a non-negative timeout makes write
 * operations synchronous on POSIX platforms.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_serial_get_tx_timeout()
 */
LELY_IO_SERIAL_INLINE int io_serial_set_tx_timeout(
		io_serial_t *serial, int optval);

static inline io_ctx_t *
io_serial_get_ctx(const io_serial_t *serial)
{
	return io_dev_get_ctx(io_serial_get_dev(serial));
}

static inline ev_exec_t *
io_serial_get_exec(const io_serial_t *serial)
{
	return io_dev_get_exec(io_serial_get_dev(serial));
}

static inline size_t
io_serial_cancel(io_serial_t *serial, struct ev_task *task)
{
	return io_dev_cancel(io_serial_get_dev(serial), task);
}

static inline size_t
io_serial_abort(io_serial_t *serial, struct ev_task *task)
{
	return io_dev_abort(io_serial_get_dev(serial), task);
}

static inline io_dev_t *
io_serial_get_dev(const io_serial_t *serial)
{
	return io_stream_get_dev(io_serial_get_stream(serial));
}

static inline ssize_t
io_serial_readv(io_serial_t *serial, const struct io_buf *buf, int bufcnt)
{
	return io_stream_readv(io_serial_get_stream(serial), buf, bufcnt);
}

static inline void
io_serial_submit_readv(io_serial_t *serial, struct io_stream_readv *readv)
{
	io_stream_submit_readv(io_serial_get_stream(serial), readv);
}

static inline size_t
io_serial_cancel_readv(io_serial_t *serial, struct io_stream_readv *readv)
{
	return io_stream_cancel_readv(io_serial_get_stream(serial), readv);
}

static inline size_t
io_serial_abort_readv(io_serial_t *serial, struct io_stream_readv *readv)
{
	return io_stream_abort_readv(io_serial_get_stream(serial), readv);
}

static inline ev_future_t *
io_serial_async_readv(io_serial_t *serial, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt,
		struct io_stream_readv **preadv)
{
	return io_stream_async_readv(io_serial_get_stream(serial), exec, buf,
			bufcnt, preadv);
}

static inline ssize_t
io_serial_read(io_serial_t *serial, void *buf, size_t nbytes)
{
	return io_stream_read(io_serial_get_stream(serial), buf, nbytes);
}

static inline void
io_serial_submit_read(io_serial_t *serial, struct io_stream_read *read)
{
	io_stream_submit_read(io_serial_get_stream(serial), read);
}

static inline size_t
io_serial_cancel_read(io_serial_t *serial, struct io_stream_read *read)
{
	return io_stream_cancel_read(io_serial_get_stream(serial), read);
}

static inline size_t
io_serial_abort_read(io_serial_t *serial, struct io_stream_read *read)
{
	return io_stream_abort_read(io_serial_get_stream(serial), read);
}

static inline ev_future_t *
io_serial_async_read(io_serial_t *serial, ev_exec_t *exec, void *buf,
		size_t nbytes, struct io_stream_read **pread)
{
	return io_stream_async_read(
			io_serial_get_stream(serial), exec, buf, nbytes, pread);
}

static inline ssize_t
io_serial_writev(io_serial_t *serial, const struct io_buf *buf, int bufcnt)
{
	return io_stream_writev(io_serial_get_stream(serial), buf, bufcnt);
}

static inline void
io_serial_submit_writev(io_serial_t *serial, struct io_stream_writev *writev)
{
	io_stream_submit_writev(io_serial_get_stream(serial), writev);
}

static inline size_t
io_serial_cancel_writev(io_serial_t *serial, struct io_stream_writev *writev)
{
	return io_stream_cancel_writev(io_serial_get_stream(serial), writev);
}

static inline size_t
io_serial_abort_writev(io_serial_t *serial, struct io_stream_writev *writev)
{
	return io_stream_abort_writev(io_serial_get_stream(serial), writev);
}

static inline ev_future_t *
io_serial_async_writev(io_serial_t *serial, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt,
		struct io_stream_writev **pwritev)
{
	return io_stream_async_writev(io_serial_get_stream(serial), exec, buf,
			bufcnt, pwritev);
}

static inline ssize_t
io_serial_write(io_serial_t *serial, const void *buf, size_t nbytes)
{
	return io_stream_write(io_serial_get_stream(serial), buf, nbytes);
}

static inline void
io_serial_submit_write(io_serial_t *serial, struct io_stream_write *write)
{
	io_stream_submit_write(io_serial_get_stream(serial), write);
}

static inline size_t
io_serial_cancel_write(io_serial_t *serial, struct io_stream_write *write)
{
	return io_stream_cancel_write(io_serial_get_stream(serial), write);
}

static inline size_t
io_serial_abort_write(io_serial_t *serial, struct io_stream_write *write)
{
	return io_stream_abort_write(io_serial_get_stream(serial), write);
}

static inline ev_future_t *
io_serial_async_write(io_serial_t *serial, ev_exec_t *exec, const void *buf,
		size_t nbytes, struct io_stream_write **pwrite)
{
	return io_stream_async_write(io_serial_get_stream(serial), exec, buf,
			nbytes, pwrite);
}

inline io_stream_t *
io_serial_get_stream(const io_serial_t *serial)
{
	return (*serial)->get_stream(serial);
}

inline int
io_serial_send_break(io_serial_t *serial)
{
	return (*serial)->send_break(serial);
}

inline int
io_serial_flush(io_serial_t *serial)
{
	return (*serial)->flush(serial);
}

inline int
io_serial_purge(io_serial_t *serial, int how)
{
	return (*serial)->purge(serial, how);
}

inline int
io_serial_get_baud_rate(const io_serial_t *serial)
{
	return (*serial)->get_baud_rate(serial);
}

inline int
io_serial_set_baud_rate(io_serial_t *serial, int optval)
{
	return (*serial)->set_baud_rate(serial, optval);
}

inline int
io_serial_get_flow_ctrl(const io_serial_t *serial)
{
	return (*serial)->get_flow_ctrl(serial);
}

inline int
io_serial_set_flow_ctrl(io_serial_t *serial, int optval)
{
	return (*serial)->set_flow_ctrl(serial, optval);
}

inline int
io_serial_get_parity(const io_serial_t *serial)
{
	return (*serial)->get_parity(serial);
}

inline int
io_serial_set_parity(io_serial_t *serial, int optval)
{
	return (*serial)->set_parity(serial, optval);
}

inline int
io_serial_get_stop_bits(const io_serial_t *serial)
{
	return (*serial)->get_stop_bits(serial);
}

inline int
io_serial_set_stop_bits(io_serial_t *serial, int optval)
{
	return (*serial)->set_stop_bits(serial, optval);
}

inline int
io_serial_get_char_size(const io_serial_t *serial)
{
	return (*serial)->get_char_size(serial);
}

inline int
io_serial_set_char_size(io_serial_t *serial, int optval)
{
	return (*serial)->set_char_size(serial, optval);
}

inline int
io_serial_get_rx_timeout(const io_serial_t *serial)
{
	return (*serial)->get_rx_timeout(serial);
}

inline int
io_serial_set_rx_timeout(io_serial_t *serial, int optval)
{
	return (*serial)->set_rx_timeout(serial, optval);
}

inline int
io_serial_get_tx_timeout(const io_serial_t *serial)
{
	return (*serial)->get_rx_timeout(serial);
}

inline int
io_serial_set_tx_timeout(io_serial_t *serial, int optval)
{
	return (*serial)->set_rx_timeout(serial, optval);
}

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_SERIAL_H_
