/**@file
 * This header file is part of the I/O library; it contains the abstract
 * Bluetooth RFCOMM socket interface.
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

#ifndef LELY_IO2_RFCOMM_H_
#define LELY_IO2_RFCOMM_H_

#include <lely/io2/bth.h>
#include <lely/io2/endp.h>
#include <lely/io2/sock_stream.h>
#include <lely/io2/sock_stream_srv.h>

#ifndef LELY_IO_RFCOMM_INLINE
#define LELY_IO_RFCOMM_INLINE static inline
#endif

/// The SDP UUID for RFCOMM.
#define IO_BTHPROTO_RFCOMM 0x0003

/// A Bluetooth RFCOMM endpoint.
struct io_endp_bth_rfcomm {
	/// &#bth
	struct io_addr *addr;
	/// `sizeof(struct io_endp_bth_rfcomm)`
	int len;
	/// #IO_BTHPROTO_RFCOMM
	int protocol;
	/// The channel number.
	uint_least8_t channel;
	/// The IPv4 network address.
	struct io_addr_bth bth;
};

/**
 * The static initializer for #io_endp_bth_rfcomm. <b>self</b> MUST be the
 * address of the struct being initialized.
 */
#define IO_ENDP_BTH_RFCOMM_INIT(self) \
	{ \
		(struct io_addr *)&(self)->bth, \
				sizeof(struct io_endp_bth_rfcomm), \
				IO_BTHPROTO_RFCOMM, 0, IO_ADDR_BTH_INIT \
	}

union io_endp_bth_rfcomm_ {
	struct io_endp _endp;
	struct io_endp_storage _storage;
	struct io_endp_bth_rfcomm _bth_rfcomm;
};

/// An abstract Bluetooth RFCOMM server.
typedef const struct io_rfcomm_srv_vtbl *const io_rfcomm_srv_t;

/// An abstract Bluetooth RFCOMM socket.
typedef const struct io_rfcomm_vtbl *const io_rfcomm_t;

#ifdef __cplusplus
extern "C" {
#endif

struct io_rfcomm_srv_vtbl {
	io_sock_stream_srv_t *(*get_sock_stream_srv)(
			const io_rfcomm_srv_t *rfcomm);
	int (*open)(io_rfcomm_srv_t *rfcomm);
};

struct io_rfcomm_vtbl {
	io_sock_stream_t *(*get_sock_stream)(const io_rfcomm_t *rfcomm);
	int (*open)(io_rfcomm_t *rfcomm);
};

/// @see io_dev_get_ctx()
static inline io_ctx_t *io_rfcomm_srv_get_ctx(const io_rfcomm_srv_t *rfcomm);

/// @see io_dev_get_exec()
static inline ev_exec_t *io_rfcomm_srv_get_exec(const io_rfcomm_srv_t *rfcomm);

/// @see io_dev_cancel()
static inline size_t io_rfcomm_srv_cancel(
		io_rfcomm_srv_t *rfcomm, struct ev_task *task);

/// @see io_dev_abort()
static inline size_t io_rfcomm_srv_abort(
		io_rfcomm_srv_t *rfcomm, struct ev_task *task);

/// @see io_sock_bind()
static inline int io_rfcomm_srv_bind(io_rfcomm_srv_t *rfcomm,
		const struct io_endp *endp, int reuseaddr);

/// @see io_sock_getsockname()
static inline int io_rfcomm_srv_getsockname(
		const io_rfcomm_srv_t *rfcomm, struct io_endp *endp);

/// @see io_sock_is_open()
static inline int io_rfcomm_srv_is_open(const io_rfcomm_srv_t *rfcomm);

/// @see io_sock_close()
static inline int io_rfcomm_srv_close(io_rfcomm_srv_t *rfcomm);

/// @see io_sock_wait()
static inline int io_rfcomm_srv_wait(
		io_rfcomm_srv_t *rfcomm, int *events, int timeout);

/// @see io_sock_submit_wait()
static inline void io_rfcomm_srv_submit_wait(
		io_rfcomm_srv_t *rfcomm, struct io_sock_wait *wait);

/// @see io_sock_cancel_wait()
static inline size_t io_rfcomm_srv_cancel_wait(
		io_rfcomm_srv_t *rfcomm, struct io_sock_wait *wait);

/// @see io_sock_abort_wait()
static inline size_t io_rfcomm_srv_abort_wait(
		io_rfcomm_srv_t *rfcomm, struct io_sock_wait *wait);

/// @see io_sock_async_wait()
static inline ev_future_t *io_rfcomm_srv_async_wait(io_rfcomm_srv_t *rfcomm,
		ev_exec_t *exec, int *events, struct io_sock_wait **pwait);

/// @see io_sock_get_error()
static inline int io_rfcomm_srv_get_error(io_rfcomm_srv_t *rfcomm);

/// @see io_sock_stream_srv_get_maxconn()
static inline int io_rfcomm_srv_get_maxconn(const io_rfcomm_srv_t *rfcomm);

/// @see io_sock_stream_srv_listen()
static inline int io_rfcomm_srv_listen(io_rfcomm_srv_t *rfcomm, int backlog);

/// @see io_sock_stream_srv_is_listening()
static inline int io_rfcomm_srv_is_listening(const io_rfcomm_srv_t *rfcomm);

/// @see io_sock_stream_srv_accept()
static inline int io_rfcomm_srv_accept(io_rfcomm_srv_t *rfcomm,
		io_rfcomm_t *sock, struct io_endp *endp, int timeout);

/// @see io_sock_stream_srv_submit_accept()
static inline void io_rfcomm_srv_submit_accept(io_rfcomm_srv_t *rfcomm,
		struct io_sock_stream_srv_accept *accept);

/// @see io_sock_stream_srv_cancel_accept()
static inline size_t io_rfcomm_srv_cancel_accept(io_rfcomm_srv_t *rfcomm,
		struct io_sock_stream_srv_accept *accept);

/// @see io_sock_stream_srv_abort_accept()
static inline size_t io_rfcomm_srv_abort_accept(io_rfcomm_srv_t *rfcomm,
		struct io_sock_stream_srv_accept *accept);

/// @see io_sock_stream_srv_async_accept()
static inline ev_future_t *io_rfcomm_srv_async_accept(io_rfcomm_srv_t *rfcomm,
		ev_exec_t *exec, io_rfcomm_t *sock, struct io_endp *endp,
		struct io_sock_stream_srv_accept **paccept);

/**
 * Returns a pointer to the abstract I/O device representing the Bluetooth
 * RFCOMM server.
 */
static inline io_dev_t *io_rfcomm_srv_get_dev(const io_rfcomm_srv_t *rfcomm);

/**
 * Returns a pointer to the abstract socket representing the Bluetooth RFCOMM
 * server.
 */
static inline io_sock_t *io_rfcomm_srv_get_sock(const io_rfcomm_srv_t *rfcomm);

/**
 * Returns a pointer to the abstract stream socket representing the Bluetooth
 * RFCOMM server.
 */
LELY_IO_RFCOMM_INLINE io_sock_stream_srv_t *io_rfcomm_srv_get_sock_stream_srv(
		const io_rfcomm_srv_t *rfcomm);

/**
 * Opens a Bluetooth socket that can be used to accept incoming RFCOMM
 * connections.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @post on success, io_sock_is_open() returns 1.
 */
LELY_IO_RFCOMM_INLINE int io_rfcomm_srv_open(io_rfcomm_srv_t *rfcomm);

/// @see io_dev_get_ctx()
static inline io_ctx_t *io_rfcomm_get_ctx(const io_rfcomm_t *rfcomm);

/// @see io_dev_get_exec()
static inline ev_exec_t *io_rfcomm_get_exec(const io_rfcomm_t *rfcomm);

/// @see io_dev_cancel()
static inline size_t io_rfcomm_cancel(
		io_rfcomm_t *rfcomm, struct ev_task *task);

/// @see io_dev_abort()
static inline size_t io_rfcomm_abort(io_rfcomm_t *rfcomm, struct ev_task *task);

/// @see io_sock_bind()
static inline int io_rfcomm_bind(
		io_rfcomm_t *rfcomm, const struct io_endp *endp, int reuseaddr);

/// @see io_sock_getsockname()
static inline int io_rfcomm_getsockname(
		const io_rfcomm_t *rfcomm, struct io_endp *endp);

/// @see io_sock_is_open()
static inline int io_rfcomm_is_open(const io_rfcomm_t *rfcomm);

/// @see io_sock_close()
static inline int io_rfcomm_close(io_rfcomm_t *rfcomm);

/// @see io_sock_wait()
static inline int io_rfcomm_wait(io_rfcomm_t *rfcomm, int *events, int timeout);

/// @see io_sock_submit_wait()
static inline void io_rfcomm_submit_wait(
		io_rfcomm_t *rfcomm, struct io_sock_wait *wait);

/// @see io_sock_cancel_wait()
static inline size_t io_rfcomm_cancel_wait(
		io_rfcomm_t *rfcomm, struct io_sock_wait *wait);

/// @see io_sock_abort_wait()
static inline size_t io_rfcomm_abort_wait(
		io_rfcomm_t *rfcomm, struct io_sock_wait *wait);

/// @see io_sock_async_wait()
static inline ev_future_t *io_rfcomm_async_wait(io_rfcomm_t *rfcomm,
		ev_exec_t *exec, int *events, struct io_sock_wait **pwait);

/// @see io_sock_get_error()
static inline int io_rfcomm_get_error(io_rfcomm_t *rfcomm);

/// @see io_sock_get_nread()
static inline int io_rfcomm_get_nread(const io_rfcomm_t *rfcomm);

/// @see io_sock_get_dontroute()
static inline int io_rfcomm_get_dontroute(const io_rfcomm_t *rfcomm);

/// @see io_sock_set_dontroute()
static inline int io_rfcomm_set_dontroute(io_rfcomm_t *rfcomm, int optval);

/// @see io_sock_get_rcvbuf()
static inline int io_rfcomm_get_rcvbuf(const io_rfcomm_t *rfcomm);

/// @see io_sock_set_rcvbuf()
static inline int io_rfcomm_set_rcvbuf(io_rfcomm_t *rfcomm, int optval);

/// @see io_sock_get_sndbuf()
static inline int io_rfcomm_get_sndbuf(const io_rfcomm_t *rfcomm);

/// @see io_sock_set_sndbuf()
static inline int io_rfcomm_set_sndbuf(io_rfcomm_t *rfcomm, int optval);

/// @see io_stream_readv()
static inline ssize_t io_rfcomm_readv(
		io_rfcomm_t *rfcomm, const struct io_buf *buf, int bufcnt);

/// @see io_stream_submit_readv()
static inline void io_rfcomm_submit_readv(
		io_rfcomm_t *rfcomm, struct io_stream_readv *readv);

/// @see io_stream_cancel_readv()
static inline size_t io_rfcomm_cancel_readv(
		io_rfcomm_t *rfcomm, struct io_stream_readv *readv);

/// @see io_stream_abort_readv()
static inline size_t io_rfcomm_abort_readv(
		io_rfcomm_t *rfcomm, struct io_stream_readv *readv);

/// @see io_stream_async_readv()
static inline ev_future_t *io_rfcomm_async_readv(io_rfcomm_t *rfcomm,
		ev_exec_t *exec, const struct io_buf *buf, int bufcnt,
		struct io_stream_readv **preadv);

/// @see io_stream_read()
static inline ssize_t io_rfcomm_read(
		io_rfcomm_t *rfcomm, void *buf, size_t nbytes);

/// @see io_stream_submit_read()
static inline void io_rfcomm_submit_read(
		io_rfcomm_t *rfcomm, struct io_stream_read *read);

/// @see io_stream_cancel_read()
static inline size_t io_rfcomm_cancel_read(
		io_rfcomm_t *rfcomm, struct io_stream_read *read);

/// @see io_stream_abort_read()
static inline size_t io_rfcomm_abort_read(
		io_rfcomm_t *rfcomm, struct io_stream_read *read);

/// @see io_stream_async_read()
static inline ev_future_t *io_rfcomm_async_read(io_rfcomm_t *rfcomm,
		ev_exec_t *exec, void *buf, size_t nbytes,
		struct io_stream_read **pread);

/// @see io_stream_writev()
static inline ssize_t io_rfcomm_writev(
		io_rfcomm_t *rfcomm, const struct io_buf *buf, int bufcnt);

/// @see io_stream_submit_writev()
static inline void io_rfcomm_submit_writev(
		io_rfcomm_t *rfcomm, struct io_stream_writev *writev);

/// @see io_stream_cancel_writev()
static inline size_t io_rfcomm_cancel_writev(
		io_rfcomm_t *rfcomm, struct io_stream_writev *writev);

/// @see io_stream_abort_writev()
static inline size_t io_rfcomm_abort_writev(
		io_rfcomm_t *rfcomm, struct io_stream_writev *writev);

/// @see io_stream_async_writev()
static inline ev_future_t *io_rfcomm_async_writev(io_rfcomm_t *rfcomm,
		ev_exec_t *exec, const struct io_buf *buf, int bufcnt,
		struct io_stream_writev **pwritev);

/// @see io_stream_write()
static inline ssize_t io_rfcomm_write(
		io_rfcomm_t *rfcomm, const void *buf, size_t nbytes);

/// @see io_stream_submit_write()
static inline void io_rfcomm_submit_write(
		io_rfcomm_t *rfcomm, struct io_stream_write *write);

/// @see io_stream_cancel_write()
static inline size_t io_rfcomm_cancel_write(
		io_rfcomm_t *rfcomm, struct io_stream_write *write);

/// @see io_stream_abort_write()
static inline size_t io_rfcomm_abort_write(
		io_rfcomm_t *rfcomm, struct io_stream_write *write);

/// @see io_sock_stream_connect()
static inline int io_rfcomm_connect(
		io_rfcomm_t *rfcomm, const struct io_endp *endp);

/// @see io_sock_stream_submit_connect()
static inline void io_rfcomm_submit_connect(
		io_rfcomm_t *rfcomm, struct io_sock_stream_connect *connect);

/// @see io_sock_stream_cancel_connect()
static inline size_t io_rfcomm_cancel_connect(
		io_rfcomm_t *rfcomm, struct io_sock_stream_connect *connect);

/// @see io_sock_stream_abort_connect()
static inline size_t io_rfcomm_abort_connect(
		io_rfcomm_t *rfcomm, struct io_sock_stream_connect *connect);

/// @see io_sock_stream_async_connect()
static inline ev_future_t *io_rfcomm_async_connect(io_rfcomm_t *rfcomm,
		ev_exec_t *exec, const struct io_endp *endp,
		struct io_sock_stream_connect **pconnect);

/// @see io_sock_stream_getpeername()
static inline int io_rfcomm_getpeername(
		const io_rfcomm_t *rfcomm, struct io_endp *endp);

/// @see io_sock_stream_recvmsg()
static inline ssize_t io_rfcomm_recvmsg(io_rfcomm_t *rfcomm,
		const struct io_buf *buf, int bufcnt, int *flags, int timeout);

/// @see io_sock_stream_submit_recvmsg()
static inline void io_rfcomm_submit_recvmsg(
		io_rfcomm_t *rfcomm, struct io_sock_stream_recvmsg *recvmsg);

/// @see io_sock_stream_cancel_recvmsg()
static inline size_t io_rfcomm_cancel_recvmsg(
		io_rfcomm_t *rfcomm, struct io_sock_stream_recvmsg *recvmsg);

/// @see io_sock_stream_abort_recvmsg()
static inline size_t io_rfcomm_abort_recvmsg(
		io_rfcomm_t *rfcomm, struct io_sock_stream_recvmsg *recvmsg);

/// @see io_sock_stream_async_recvmsg()
static inline ev_future_t *io_rfcomm_async_recvmsg(io_rfcomm_t *rfcomm,
		ev_exec_t *exec, const struct io_buf *buf, int bufcnt,
		int *flags, struct io_sock_stream_recvmsg **precvmsg);

/// @see io_sock_stream_recv()
static inline ssize_t io_rfcomm_recv(io_rfcomm_t *rfcomm, void *buf,
		size_t nbytes, int *flags, int timeout);

/// @see io_sock_stream_submit_recv()
static inline void io_rfcomm_submit_recv(
		io_rfcomm_t *rfcomm, struct io_sock_stream_recv *recv);

/// @see io_sock_stream_cancel_recv()
static inline size_t io_rfcomm_cancel_recv(
		io_rfcomm_t *rfcomm, struct io_sock_stream_recv *recv);

/// @see io_sock_stream_abort_recv()
static inline size_t io_rfcomm_abort_recv(
		io_rfcomm_t *rfcomm, struct io_sock_stream_recv *recv);

/// @see io_sock_stream_async_recv()
static inline ev_future_t *io_rfcomm_async_recv(io_rfcomm_t *rfcomm,
		ev_exec_t *exec, void *buf, size_t nbytes, int *flags,
		struct io_sock_stream_recv **precv);

/// @see io_sock_stream_sendmsg()
static inline ssize_t io_rfcomm_sendmsg(io_rfcomm_t *rfcomm,
		const struct io_buf *buf, int bufcnt, int flags, int timeout);

/// @see io_sock_stream_submit_sendmsg()
static inline void io_rfcomm_submit_sendmsg(
		io_rfcomm_t *rfcomm, struct io_sock_stream_sendmsg *sendmsg);

/// @see io_sock_stream_cancel_sendmsg()
static inline size_t io_rfcomm_cancel_sendmsg(
		io_rfcomm_t *rfcomm, struct io_sock_stream_sendmsg *sendmsg);

/// @see io_sock_stream_abort_sendmsg()
static inline size_t io_rfcomm_abort_sendmsg(
		io_rfcomm_t *rfcomm, struct io_sock_stream_sendmsg *sendmsg);

/// @see io_sock_stream_async_sendmsg()
static inline ev_future_t *io_rfcomm_async_sendmsg(io_rfcomm_t *rfcomm,
		ev_exec_t *exec, const struct io_buf *buf, int bufcnt,
		int flags, struct io_sock_stream_sendmsg **psendmsg);

/// @see io_sock_stream_send()
static inline ssize_t io_rfcomm_send(io_rfcomm_t *rfcomm, const void *buf,
		size_t nbytes, int flags, int timeout);

/// @see io_sock_stream_submit_send()
static inline void io_rfcomm_submit_send(
		io_rfcomm_t *rfcomm, struct io_sock_stream_send *send);

/// @see io_sock_stream_cancel_send()
static inline size_t io_rfcomm_cancel_send(
		io_rfcomm_t *rfcomm, struct io_sock_stream_send *send);

/// @see io_sock_stream_abort_send()
static inline size_t io_rfcomm_abort_send(
		io_rfcomm_t *rfcomm, struct io_sock_stream_send *send);

/// @see io_sock_stream_async_send()
static inline ev_future_t *io_rfcomm_async_send(io_rfcomm_t *rfcomm,
		ev_exec_t *exec, const void *buf, size_t nbytes, int flags,
		struct io_sock_stream_send **psend);

/// @see io_sock_stream_shutdown()
static inline int io_rfcomm_shutdown(io_rfcomm_t *rfcomm, int how);

/// @see io_sock_stream_get_linger()
static inline int io_rfcomm_get_linger(
		const io_rfcomm_t *rfcomm, int *ponoff, int *plinger);

/// @see io_sock_stream_set_linger()
static inline int io_rfcomm_set_linger(
		io_rfcomm_t *rfcomm, int onoff, int linger);

/**
 * Returns a pointer to the abstract I/O device representing the Bluetooth
 * RFCOMM socket.
 */
static inline io_dev_t *io_rfcomm_get_dev(const io_rfcomm_t *rfcomm);

/**
 * Returns a pointer to the abstract socket representing the Bluetooth RFCOMM
 * socket.
 */
static inline io_sock_t *io_rfcomm_get_sock(const io_rfcomm_t *rfcomm);

/**
 * Returns a pointer to the abstract stream representing the Bluetooth RFCOMM
 * socket.
 */
static inline io_stream_t *io_rfcomm_get_stream(const io_rfcomm_t *rfcomm);

/**
 * Returns a pointer to the abstract stream socket representing the Bluetooth
 * RFCOMM socket.
 */
LELY_IO_RFCOMM_INLINE io_sock_stream_t *io_rfcomm_get_sock_stream(
		const io_rfcomm_t *rfcomm);

/**
 * Opens a Bluetooth socket that can be used to connect to an RFCOMM server.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @post on success, io_sock_is_open() returns 1.
 */
LELY_IO_RFCOMM_INLINE int io_rfcomm_open(io_rfcomm_t *rfcomm);

static inline io_ctx_t *
io_rfcomm_srv_get_ctx(const io_rfcomm_srv_t *rfcomm)
{
	return io_dev_get_ctx(io_rfcomm_srv_get_dev(rfcomm));
}

static inline ev_exec_t *
io_rfcomm_srv_get_exec(const io_rfcomm_srv_t *rfcomm)
{
	return io_dev_get_exec(io_rfcomm_srv_get_dev(rfcomm));
}

static inline size_t
io_rfcomm_srv_cancel(io_rfcomm_srv_t *rfcomm, struct ev_task *task)
{
	return io_dev_cancel(io_rfcomm_srv_get_dev(rfcomm), task);
}

static inline size_t
io_rfcomm_srv_abort(io_rfcomm_srv_t *rfcomm, struct ev_task *task)
{
	return io_dev_abort(io_rfcomm_srv_get_dev(rfcomm), task);
}

static inline int
io_rfcomm_srv_bind(io_rfcomm_srv_t *rfcomm, const struct io_endp *endp,
		int reuseaddr)
{
	return io_sock_bind(io_rfcomm_srv_get_sock(rfcomm), endp, reuseaddr);
}

static inline int
io_rfcomm_srv_getsockname(const io_rfcomm_srv_t *rfcomm, struct io_endp *endp)
{
	return io_sock_getsockname(io_rfcomm_srv_get_sock(rfcomm), endp);
}

static inline int
io_rfcomm_srv_is_open(const io_rfcomm_srv_t *rfcomm)
{
	return io_sock_is_open(io_rfcomm_srv_get_sock(rfcomm));
}

static inline int
io_rfcomm_srv_close(io_rfcomm_srv_t *rfcomm)
{
	return io_sock_close(io_rfcomm_srv_get_sock(rfcomm));
}

static inline int
io_rfcomm_srv_wait(io_rfcomm_srv_t *rfcomm, int *events, int timeout)
{
	return io_sock_wait(io_rfcomm_srv_get_sock(rfcomm), events, timeout);
}

static inline void
io_rfcomm_srv_submit_wait(io_rfcomm_srv_t *rfcomm, struct io_sock_wait *wait)
{
	io_sock_submit_wait(io_rfcomm_srv_get_sock(rfcomm), wait);
}

static inline size_t
io_rfcomm_srv_cancel_wait(io_rfcomm_srv_t *rfcomm, struct io_sock_wait *wait)
{
	return io_sock_cancel_wait(io_rfcomm_srv_get_sock(rfcomm), wait);
}

static inline size_t
io_rfcomm_srv_abort_wait(io_rfcomm_srv_t *rfcomm, struct io_sock_wait *wait)
{
	return io_sock_abort_wait(io_rfcomm_srv_get_sock(rfcomm), wait);
}

static inline ev_future_t *
io_rfcomm_srv_async_wait(io_rfcomm_srv_t *rfcomm, ev_exec_t *exec, int *events,
		struct io_sock_wait **pwait)
{
	return io_sock_async_wait(
			io_rfcomm_srv_get_sock(rfcomm), exec, events, pwait);
}

static inline int
io_rfcomm_srv_get_error(io_rfcomm_srv_t *rfcomm)
{
	return io_sock_get_error(io_rfcomm_srv_get_sock(rfcomm));
}

static inline int
io_rfcomm_srv_get_maxconn(const io_rfcomm_srv_t *rfcomm)
{
	return io_sock_stream_srv_get_maxconn(
			io_rfcomm_srv_get_sock_stream_srv(rfcomm));
}

static inline int
io_rfcomm_srv_listen(io_rfcomm_srv_t *rfcomm, int backlog)
{
	return io_sock_stream_srv_listen(
			io_rfcomm_srv_get_sock_stream_srv(rfcomm), backlog);
}

static inline int
io_rfcomm_srv_is_listening(const io_rfcomm_srv_t *rfcomm)
{
	return io_sock_stream_srv_is_listening(
			io_rfcomm_srv_get_sock_stream_srv(rfcomm));
}

static inline int
io_rfcomm_srv_accept(io_rfcomm_srv_t *rfcomm, io_rfcomm_t *sock,
		struct io_endp *endp, int timeout)
{
	return io_sock_stream_srv_accept(
			io_rfcomm_srv_get_sock_stream_srv(rfcomm),
			io_rfcomm_get_sock_stream(sock), endp, timeout);
}

static inline void
io_rfcomm_srv_submit_accept(io_rfcomm_srv_t *rfcomm,
		struct io_sock_stream_srv_accept *accept)
{
	io_sock_stream_srv_submit_accept(
			io_rfcomm_srv_get_sock_stream_srv(rfcomm), accept);
}

static inline size_t
io_rfcomm_srv_cancel_accept(io_rfcomm_srv_t *rfcomm,
		struct io_sock_stream_srv_accept *accept)
{
	return io_sock_stream_srv_cancel_accept(
			io_rfcomm_srv_get_sock_stream_srv(rfcomm), accept);
}

static inline size_t
io_rfcomm_srv_abort_accept(io_rfcomm_srv_t *rfcomm,
		struct io_sock_stream_srv_accept *accept)
{
	return io_sock_stream_srv_abort_accept(
			io_rfcomm_srv_get_sock_stream_srv(rfcomm), accept);
}

static inline ev_future_t *
io_rfcomm_srv_async_accept(io_rfcomm_srv_t *rfcomm, ev_exec_t *exec,
		io_rfcomm_t *sock, struct io_endp *endp,
		struct io_sock_stream_srv_accept **paccept)
{
	return io_sock_stream_srv_async_accept(
			io_rfcomm_srv_get_sock_stream_srv(rfcomm), exec,
			io_rfcomm_get_sock_stream(sock), endp, paccept);
}

static inline io_dev_t *
io_rfcomm_srv_get_dev(const io_rfcomm_srv_t *rfcomm)
{
	return io_sock_stream_srv_get_dev(
			io_rfcomm_srv_get_sock_stream_srv(rfcomm));
}

static inline io_sock_t *
io_rfcomm_srv_get_sock(const io_rfcomm_srv_t *rfcomm)
{
	return io_sock_stream_srv_get_sock(
			io_rfcomm_srv_get_sock_stream_srv(rfcomm));
}

inline io_sock_stream_srv_t *
io_rfcomm_srv_get_sock_stream_srv(const io_rfcomm_srv_t *rfcomm)
{
	return (*rfcomm)->get_sock_stream_srv(rfcomm);
}

inline int
io_rfcomm_srv_open(io_rfcomm_srv_t *rfcomm)
{
	return (*rfcomm)->open(rfcomm);
}

static inline io_ctx_t *
io_rfcomm_get_ctx(const io_rfcomm_t *rfcomm)
{
	return io_dev_get_ctx(io_rfcomm_get_dev(rfcomm));
}

static inline ev_exec_t *
io_rfcomm_get_exec(const io_rfcomm_t *rfcomm)
{
	return io_dev_get_exec(io_rfcomm_get_dev(rfcomm));
}

static inline size_t
io_rfcomm_cancel(io_rfcomm_t *rfcomm, struct ev_task *task)
{
	return io_dev_cancel(io_rfcomm_get_dev(rfcomm), task);
}

static inline size_t
io_rfcomm_abort(io_rfcomm_t *rfcomm, struct ev_task *task)
{
	return io_dev_abort(io_rfcomm_get_dev(rfcomm), task);
}

static inline int
io_rfcomm_bind(io_rfcomm_t *rfcomm, const struct io_endp *endp, int reuseaddr)
{
	return io_sock_bind(io_rfcomm_get_sock(rfcomm), endp, reuseaddr);
}

static inline int
io_rfcomm_getsockname(const io_rfcomm_t *rfcomm, struct io_endp *endp)
{
	return io_sock_getsockname(io_rfcomm_get_sock(rfcomm), endp);
}

static inline int
io_rfcomm_is_open(const io_rfcomm_t *rfcomm)
{
	return io_sock_is_open(io_rfcomm_get_sock(rfcomm));
}

static inline int
io_rfcomm_close(io_rfcomm_t *rfcomm)
{
	return io_sock_close(io_rfcomm_get_sock(rfcomm));
}

static inline int
io_rfcomm_wait(io_rfcomm_t *rfcomm, int *events, int timeout)
{
	return io_sock_wait(io_rfcomm_get_sock(rfcomm), events, timeout);
}

static inline void
io_rfcomm_submit_wait(io_rfcomm_t *rfcomm, struct io_sock_wait *wait)
{
	io_sock_submit_wait(io_rfcomm_get_sock(rfcomm), wait);
}

static inline size_t
io_rfcomm_cancel_wait(io_rfcomm_t *rfcomm, struct io_sock_wait *wait)
{
	return io_sock_cancel_wait(io_rfcomm_get_sock(rfcomm), wait);
}

static inline size_t
io_rfcomm_abort_wait(io_rfcomm_t *rfcomm, struct io_sock_wait *wait)
{
	return io_sock_abort_wait(io_rfcomm_get_sock(rfcomm), wait);
}

static inline ev_future_t *
io_rfcomm_async_wait(io_rfcomm_t *rfcomm, ev_exec_t *exec, int *events,
		struct io_sock_wait **pwait)
{
	return io_sock_async_wait(
			io_rfcomm_get_sock(rfcomm), exec, events, pwait);
}

static inline int
io_rfcomm_get_error(io_rfcomm_t *rfcomm)
{
	return io_sock_get_error(io_rfcomm_get_sock(rfcomm));
}

static inline int
io_rfcomm_get_nread(const io_rfcomm_t *rfcomm)
{
	return io_sock_get_nread(io_rfcomm_get_sock(rfcomm));
}

static inline int
io_rfcomm_get_dontroute(const io_rfcomm_t *rfcomm)
{
	return io_sock_get_dontroute(io_rfcomm_get_sock(rfcomm));
}

static inline int
io_rfcomm_set_dontroute(io_rfcomm_t *rfcomm, int optval)
{
	return io_sock_set_dontroute(io_rfcomm_get_sock(rfcomm), optval);
}

static inline int
io_rfcomm_get_rcvbuf(const io_rfcomm_t *rfcomm)
{
	return io_sock_get_rcvbuf(io_rfcomm_get_sock(rfcomm));
}

static inline int
io_rfcomm_set_rcvbuf(io_rfcomm_t *rfcomm, int optval)
{
	return io_sock_set_rcvbuf(io_rfcomm_get_sock(rfcomm), optval);
}

static inline int
io_rfcomm_get_sndbuf(const io_rfcomm_t *rfcomm)
{
	return io_sock_get_sndbuf(io_rfcomm_get_sock(rfcomm));
}

static inline int
io_rfcomm_set_sndbuf(io_rfcomm_t *rfcomm, int optval)
{
	return io_sock_set_sndbuf(io_rfcomm_get_sock(rfcomm), optval);
}

static inline ssize_t
io_rfcomm_readv(io_rfcomm_t *rfcomm, const struct io_buf *buf, int bufcnt)
{
	return io_stream_readv(io_rfcomm_get_stream(rfcomm), buf, bufcnt);
}

static inline void
io_rfcomm_submit_readv(io_rfcomm_t *rfcomm, struct io_stream_readv *readv)
{
	io_stream_submit_readv(io_rfcomm_get_stream(rfcomm), readv);
}

static inline size_t
io_rfcomm_cancel_readv(io_rfcomm_t *rfcomm, struct io_stream_readv *readv)
{
	return io_stream_cancel_readv(io_rfcomm_get_stream(rfcomm), readv);
}

static inline size_t
io_rfcomm_abort_readv(io_rfcomm_t *rfcomm, struct io_stream_readv *readv)
{
	return io_stream_abort_readv(io_rfcomm_get_stream(rfcomm), readv);
}

static inline ev_future_t *
io_rfcomm_async_readv(io_rfcomm_t *rfcomm, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt,
		struct io_stream_readv **preadv)
{
	return io_stream_async_readv(io_rfcomm_get_stream(rfcomm), exec, buf,
			bufcnt, preadv);
}

static inline ssize_t
io_rfcomm_read(io_rfcomm_t *rfcomm, void *buf, size_t nbytes)
{
	return io_stream_read(io_rfcomm_get_stream(rfcomm), buf, nbytes);
}

static inline void
io_rfcomm_submit_read(io_rfcomm_t *rfcomm, struct io_stream_read *read)
{
	io_stream_submit_read(io_rfcomm_get_stream(rfcomm), read);
}

static inline size_t
io_rfcomm_cancel_read(io_rfcomm_t *rfcomm, struct io_stream_read *read)
{
	return io_stream_cancel_read(io_rfcomm_get_stream(rfcomm), read);
}

static inline size_t
io_rfcomm_abort_read(io_rfcomm_t *rfcomm, struct io_stream_read *read)
{
	return io_stream_abort_read(io_rfcomm_get_stream(rfcomm), read);
}

static inline ev_future_t *
io_rfcomm_async_read(io_rfcomm_t *rfcomm, ev_exec_t *exec, void *buf,
		size_t nbytes, struct io_stream_read **pread)
{
	return io_stream_async_read(
			io_rfcomm_get_stream(rfcomm), exec, buf, nbytes, pread);
}

static inline ssize_t
io_rfcomm_writev(io_rfcomm_t *rfcomm, const struct io_buf *buf, int bufcnt)
{
	return io_stream_writev(io_rfcomm_get_stream(rfcomm), buf, bufcnt);
}

static inline void
io_rfcomm_submit_writev(io_rfcomm_t *rfcomm, struct io_stream_writev *writev)
{
	io_stream_submit_writev(io_rfcomm_get_stream(rfcomm), writev);
}

static inline size_t
io_rfcomm_cancel_writev(io_rfcomm_t *rfcomm, struct io_stream_writev *writev)
{
	return io_stream_cancel_writev(io_rfcomm_get_stream(rfcomm), writev);
}

static inline size_t
io_rfcomm_abort_writev(io_rfcomm_t *rfcomm, struct io_stream_writev *writev)
{
	return io_stream_abort_writev(io_rfcomm_get_stream(rfcomm), writev);
}

static inline ev_future_t *
io_rfcomm_async_writev(io_rfcomm_t *rfcomm, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt,
		struct io_stream_writev **pwritev)
{
	return io_stream_async_writev(io_rfcomm_get_stream(rfcomm), exec, buf,
			bufcnt, pwritev);
}

static inline ssize_t
io_rfcomm_write(io_rfcomm_t *rfcomm, const void *buf, size_t nbytes)
{
	return io_stream_write(io_rfcomm_get_stream(rfcomm), buf, nbytes);
}

static inline void
io_rfcomm_submit_write(io_rfcomm_t *rfcomm, struct io_stream_write *write)
{
	io_stream_submit_write(io_rfcomm_get_stream(rfcomm), write);
}

static inline size_t
io_rfcomm_cancel_write(io_rfcomm_t *rfcomm, struct io_stream_write *write)
{
	return io_stream_cancel_write(io_rfcomm_get_stream(rfcomm), write);
}

static inline size_t
io_rfcomm_abort_write(io_rfcomm_t *rfcomm, struct io_stream_write *write)
{
	return io_stream_abort_write(io_rfcomm_get_stream(rfcomm), write);
}

static inline ev_future_t *
io_rfcomm_async_write(io_rfcomm_t *rfcomm, ev_exec_t *exec, const void *buf,
		size_t nbytes, struct io_stream_write **pwrite)
{
	return io_stream_async_write(io_rfcomm_get_stream(rfcomm), exec, buf,
			nbytes, pwrite);
}

static inline int
io_rfcomm_connect(io_rfcomm_t *rfcomm, const struct io_endp *endp)
{
	return io_sock_stream_connect(io_rfcomm_get_sock_stream(rfcomm), endp);
}

static inline void
io_rfcomm_submit_connect(
		io_rfcomm_t *rfcomm, struct io_sock_stream_connect *connect)
{
	io_sock_stream_submit_connect(
			io_rfcomm_get_sock_stream(rfcomm), connect);
}

static inline size_t
io_rfcomm_cancel_connect(
		io_rfcomm_t *rfcomm, struct io_sock_stream_connect *connect)
{
	return io_sock_stream_cancel_connect(
			io_rfcomm_get_sock_stream(rfcomm), connect);
}

static inline size_t
io_rfcomm_abort_connect(
		io_rfcomm_t *rfcomm, struct io_sock_stream_connect *connect)
{
	return io_sock_stream_abort_connect(
			io_rfcomm_get_sock_stream(rfcomm), connect);
}

static inline ev_future_t *
io_rfcomm_async_connect(io_rfcomm_t *rfcomm, ev_exec_t *exec,
		const struct io_endp *endp,
		struct io_sock_stream_connect **pconnect)
{
	return io_sock_stream_async_connect(io_rfcomm_get_sock_stream(rfcomm),
			exec, endp, pconnect);
}

static inline int
io_rfcomm_getpeername(const io_rfcomm_t *rfcomm, struct io_endp *endp)
{
	return io_sock_stream_getpeername(
			io_rfcomm_get_sock_stream(rfcomm), endp);
}

static inline ssize_t
io_rfcomm_recvmsg(io_rfcomm_t *rfcomm, const struct io_buf *buf, int bufcnt,
		int *flags, int timeout)
{
	return io_sock_stream_recvmsg(io_rfcomm_get_sock_stream(rfcomm), buf,
			bufcnt, flags, timeout);
}

static inline void
io_rfcomm_submit_recvmsg(
		io_rfcomm_t *rfcomm, struct io_sock_stream_recvmsg *recvmsg)
{
	io_sock_stream_submit_recvmsg(
			io_rfcomm_get_sock_stream(rfcomm), recvmsg);
}

static inline size_t
io_rfcomm_cancel_recvmsg(
		io_rfcomm_t *rfcomm, struct io_sock_stream_recvmsg *recvmsg)
{
	return io_sock_stream_cancel_recvmsg(
			io_rfcomm_get_sock_stream(rfcomm), recvmsg);
}

static inline size_t
io_rfcomm_abort_recvmsg(
		io_rfcomm_t *rfcomm, struct io_sock_stream_recvmsg *recvmsg)
{
	return io_sock_stream_abort_recvmsg(
			io_rfcomm_get_sock_stream(rfcomm), recvmsg);
}

static inline ev_future_t *
io_rfcomm_async_recvmsg(io_rfcomm_t *rfcomm, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt, int *flags,
		struct io_sock_stream_recvmsg **precvmsg)
{
	return io_sock_stream_async_recvmsg(io_rfcomm_get_sock_stream(rfcomm),
			exec, buf, bufcnt, flags, precvmsg);
}

static inline ssize_t
io_rfcomm_recv(io_rfcomm_t *rfcomm, void *buf, size_t nbytes, int *flags,
		int timeout)
{
	return io_sock_stream_recv(io_rfcomm_get_sock_stream(rfcomm), buf,
			nbytes, flags, timeout);
}

static inline void
io_rfcomm_submit_recv(io_rfcomm_t *rfcomm, struct io_sock_stream_recv *recv)
{
	io_sock_stream_submit_recv(io_rfcomm_get_sock_stream(rfcomm), recv);
}

static inline size_t
io_rfcomm_cancel_recv(io_rfcomm_t *rfcomm, struct io_sock_stream_recv *recv)
{
	return io_sock_stream_cancel_recv(
			io_rfcomm_get_sock_stream(rfcomm), recv);
}

static inline size_t
io_rfcomm_abort_recv(io_rfcomm_t *rfcomm, struct io_sock_stream_recv *recv)
{
	return io_sock_stream_abort_recv(
			io_rfcomm_get_sock_stream(rfcomm), recv);
}

static inline ev_future_t *
io_rfcomm_async_recv(io_rfcomm_t *rfcomm, ev_exec_t *exec, void *buf,
		size_t nbytes, int *flags, struct io_sock_stream_recv **precv)
{
	return io_sock_stream_async_recv(io_rfcomm_get_sock_stream(rfcomm),
			exec, buf, nbytes, flags, precv);
}

static inline ssize_t
io_rfcomm_sendmsg(io_rfcomm_t *rfcomm, const struct io_buf *buf, int bufcnt,
		int flags, int timeout)
{
	return io_sock_stream_sendmsg(io_rfcomm_get_sock_stream(rfcomm), buf,
			bufcnt, flags, timeout);
}

static inline void
io_rfcomm_submit_sendmsg(
		io_rfcomm_t *rfcomm, struct io_sock_stream_sendmsg *sendmsg)
{
	io_sock_stream_submit_sendmsg(
			io_rfcomm_get_sock_stream(rfcomm), sendmsg);
}

static inline size_t
io_rfcomm_cancel_sendmsg(
		io_rfcomm_t *rfcomm, struct io_sock_stream_sendmsg *sendmsg)
{
	return io_sock_stream_cancel_sendmsg(
			io_rfcomm_get_sock_stream(rfcomm), sendmsg);
}

static inline size_t
io_rfcomm_abort_sendmsg(
		io_rfcomm_t *rfcomm, struct io_sock_stream_sendmsg *sendmsg)
{
	return io_sock_stream_abort_sendmsg(
			io_rfcomm_get_sock_stream(rfcomm), sendmsg);
}

static inline ev_future_t *
io_rfcomm_async_sendmsg(io_rfcomm_t *rfcomm, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt, int flags,
		struct io_sock_stream_sendmsg **psendmsg)
{
	return io_sock_stream_async_sendmsg(io_rfcomm_get_sock_stream(rfcomm),
			exec, buf, bufcnt, flags, psendmsg);
}

static inline ssize_t
io_rfcomm_send(io_rfcomm_t *rfcomm, const void *buf, size_t nbytes, int flags,
		int timeout)
{
	return io_sock_stream_send(io_rfcomm_get_sock_stream(rfcomm), buf,
			nbytes, flags, timeout);
}

static inline void
io_rfcomm_submit_send(io_rfcomm_t *rfcomm, struct io_sock_stream_send *send)
{
	io_sock_stream_submit_send(io_rfcomm_get_sock_stream(rfcomm), send);
}

static inline size_t
io_rfcomm_cancel_send(io_rfcomm_t *rfcomm, struct io_sock_stream_send *send)
{
	return io_sock_stream_cancel_send(
			io_rfcomm_get_sock_stream(rfcomm), send);
}

static inline size_t
io_rfcomm_abort_send(io_rfcomm_t *rfcomm, struct io_sock_stream_send *send)
{
	return io_sock_stream_abort_send(
			io_rfcomm_get_sock_stream(rfcomm), send);
}

static inline ev_future_t *
io_rfcomm_async_send(io_rfcomm_t *rfcomm, ev_exec_t *exec, const void *buf,
		size_t nbytes, int flags, struct io_sock_stream_send **psend)
{
	return io_sock_stream_async_send(io_rfcomm_get_sock_stream(rfcomm),
			exec, buf, nbytes, flags, psend);
}

static inline int
io_rfcomm_shutdown(io_rfcomm_t *rfcomm, int how)
{
	return io_sock_stream_shutdown(io_rfcomm_get_sock_stream(rfcomm), how);
}

static inline int
io_rfcomm_get_linger(const io_rfcomm_t *rfcomm, int *ponoff, int *plinger)
{
	return io_sock_stream_get_linger(
			io_rfcomm_get_sock_stream(rfcomm), ponoff, plinger);
}

static inline int
io_rfcomm_set_linger(io_rfcomm_t *rfcomm, int onoff, int linger)
{
	return io_sock_stream_set_linger(
			io_rfcomm_get_sock_stream(rfcomm), onoff, linger);
}

static inline io_dev_t *
io_rfcomm_get_dev(const io_rfcomm_t *rfcomm)
{
	return io_sock_stream_get_dev(io_rfcomm_get_sock_stream(rfcomm));
}

static inline io_sock_t *
io_rfcomm_get_sock(const io_rfcomm_t *rfcomm)
{
	return io_sock_stream_get_sock(io_rfcomm_get_sock_stream(rfcomm));
}

static inline io_stream_t *
io_rfcomm_get_stream(const io_rfcomm_t *rfcomm)
{
	return io_sock_stream_get_stream(io_rfcomm_get_sock_stream(rfcomm));
}

inline io_sock_stream_t *
io_rfcomm_get_sock_stream(const io_rfcomm_t *rfcomm)
{
	return (*rfcomm)->get_sock_stream(rfcomm);
}

inline int
io_rfcomm_open(io_rfcomm_t *rfcomm)
{
	return (*rfcomm)->open(rfcomm);
}

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_RFCOMM_H_
