/**@file
 * This file is part of the I/O library; it contains the stream socket
 * implementation.
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

#include "sock_stream.h"

#if _WIN32 || (defined(_POSIX_C_SOURCE) && !defined(__NEWLIB__))

#include <lely/util/errnum.h>
#include <lely/util/util.h>

#include <assert.h>

#ifdef _POSIX_C_SOURCE
#include <unistd.h>
#endif

#ifdef _POSIX_C_SOURCE
#include "../posix/fd.h"
#endif
#include "../sock.h"
#include "../sock_stream.h"
#if _WIN32
#include "../win32/wsa.h"
#endif

static io_ctx_t *io_sock_stream_impl_dev_get_ctx(const io_dev_t *dev);
static ev_exec_t *io_sock_stream_impl_dev_get_exec(const io_dev_t *dev);
static size_t io_sock_stream_impl_dev_cancel(
		io_dev_t *dev, struct ev_task *task);
static size_t io_sock_stream_impl_dev_abort(
		io_dev_t *dev, struct ev_task *task);

// clang-format off
static const struct io_dev_vtbl io_sock_stream_impl_dev_vtbl = {
	&io_sock_stream_impl_dev_get_ctx,
	&io_sock_stream_impl_dev_get_exec,
	&io_sock_stream_impl_dev_cancel,
	&io_sock_stream_impl_dev_abort
};
// clang-format on

static io_dev_t *io_sock_stream_impl_sock_get_dev(const io_sock_t *sock);
static int io_sock_stream_impl_sock_bind(
		io_sock_t *sock, const struct io_endp *endp, int reuseaddr);
static int io_sock_stream_impl_sock_getsockname(
		const io_sock_t *sock, struct io_endp *endp);
static int io_sock_stream_impl_sock_is_open(const io_sock_t *sock);
static int io_sock_stream_impl_sock_close(io_sock_t *sock);
static int io_sock_stream_impl_sock_wait(
		io_sock_t *sock, int *events, int timeout);
static void io_sock_stream_impl_sock_submit_wait(
		io_sock_t *sock, struct io_sock_wait *wait);
static int io_sock_stream_impl_sock_get_error(io_sock_t *sock);
static int io_sock_stream_impl_sock_get_nread(const io_sock_t *sock);
static int io_sock_stream_impl_sock_get_dontroute(const io_sock_t *sock);
static int io_sock_stream_impl_sock_set_dontroute(io_sock_t *sock, int optval);
static int io_sock_stream_impl_sock_get_rcvbuf(const io_sock_t *sock);
static int io_sock_stream_impl_sock_set_rcvbuf(io_sock_t *sock, int optval);
static int io_sock_stream_impl_sock_get_sndbuf(const io_sock_t *sock);
static int io_sock_stream_impl_sock_set_sndbuf(io_sock_t *sock, int optval);

// clang-format off
static const struct io_sock_vtbl io_sock_stream_impl_sock_vtbl = {
	&io_sock_stream_impl_sock_get_dev,
	&io_sock_stream_impl_sock_bind,
	&io_sock_stream_impl_sock_getsockname,
	&io_sock_stream_impl_sock_is_open,
	&io_sock_stream_impl_sock_close,
	&io_sock_stream_impl_sock_wait,
	&io_sock_stream_impl_sock_submit_wait,
	&io_sock_stream_impl_sock_get_error,
	&io_sock_stream_impl_sock_get_nread,
	&io_sock_stream_impl_sock_get_dontroute,
	&io_sock_stream_impl_sock_set_dontroute,
	&io_sock_stream_impl_sock_get_rcvbuf,
	&io_sock_stream_impl_sock_set_rcvbuf,
	&io_sock_stream_impl_sock_get_sndbuf,
	&io_sock_stream_impl_sock_set_sndbuf
};
// clang-format on

static io_dev_t *io_sock_stream_impl_stream_get_dev(const io_stream_t *stream);
static ssize_t io_sock_stream_impl_stream_readv(
		io_stream_t *stream, const struct io_buf *buf, int bufcnt);
static void io_sock_stream_impl_stream_submit_readv(
		io_stream_t *stream, struct io_stream_readv *readv);
static ssize_t io_sock_stream_impl_stream_writev(
		io_stream_t *stream, const struct io_buf *buf, int bufcnt);
static void io_sock_stream_impl_stream_submit_writev(
		io_stream_t *stream, struct io_stream_writev *writev);

// clang-format off
static const struct io_stream_vtbl io_sock_stream_impl_stream_vtbl = {
	&io_sock_stream_impl_stream_get_dev,
	&io_sock_stream_impl_stream_readv,
	&io_sock_stream_impl_stream_submit_readv,
	&io_sock_stream_impl_stream_writev,
	&io_sock_stream_impl_stream_submit_writev
};
// clang-format on

static io_sock_t *io_sock_stream_impl_get_sock(const io_sock_stream_t *sock);
static io_stream_t *io_sock_stream_impl_get_stream(
		const io_sock_stream_t *sock);
static int io_sock_stream_impl_connect(
		io_sock_stream_t *sock, const struct io_endp *endp);
static void io_sock_stream_impl_submit_connect(
		io_sock_stream_t *sock, struct io_sock_stream_connect *connect);
static int io_sock_stream_impl_getpeername(
		const io_sock_stream_t *sock, struct io_endp *endp);
static ssize_t io_sock_stream_impl_recvmsg(io_sock_stream_t *sock,
		const struct io_buf *buf, int bufcnt, int *flags, int timeout);
static void io_sock_stream_impl_submit_recvmsg(
		io_sock_stream_t *sock, struct io_sock_stream_recvmsg *recvmsg);
static ssize_t io_sock_stream_impl_sendmsg(io_sock_stream_t *sock,
		const struct io_buf *buf, int bufcnt, int flags, int timeout);
static void io_sock_stream_impl_submit_sendmsg(
		io_sock_stream_t *sock, struct io_sock_stream_sendmsg *sendmsg);
static int io_sock_stream_impl_shutdown(io_sock_stream_t *sock, int type);
static int io_sock_stream_impl_get_keepalive(const io_sock_stream_t *sock);
static int io_sock_stream_impl_set_keepalive(
		io_sock_stream_t *sock, int optval);
static int io_sock_stream_impl_get_linger(
		const io_sock_stream_t *sock, int *ponoff, int *plinger);
static int io_sock_stream_impl_set_linger(
		io_sock_stream_t *sock, int onoff, int linger);
static int io_sock_stream_impl_get_oobinline(const io_sock_stream_t *sock);
static int io_sock_stream_impl_set_oobinline(
		io_sock_stream_t *sock, int optval);
static int io_sock_stream_impl_atmark(const io_sock_stream_t *sock);

// clang-format off
static const struct io_sock_stream_vtbl io_sock_stream_impl_vtbl = {
	&io_sock_stream_impl_get_sock,
	&io_sock_stream_impl_get_stream,
	&io_sock_stream_impl_connect,
	&io_sock_stream_impl_submit_connect,
	&io_sock_stream_impl_getpeername,
	&io_sock_stream_impl_recvmsg,
	&io_sock_stream_impl_submit_recvmsg,
	&io_sock_stream_impl_sendmsg,
	&io_sock_stream_impl_submit_sendmsg,
	&io_sock_stream_impl_shutdown,
	&io_sock_stream_impl_get_keepalive,
	&io_sock_stream_impl_set_keepalive,
	&io_sock_stream_impl_get_linger,
	&io_sock_stream_impl_set_linger,
	&io_sock_stream_impl_get_oobinline,
	&io_sock_stream_impl_set_oobinline,
	&io_sock_stream_impl_atmark
};
// clang-format on

static void io_sock_stream_impl_svc_shutdown(struct io_svc *svc);

// clang-format off
static const struct io_svc_vtbl io_sock_stream_impl_svc_vtbl = {
	NULL,
	&io_sock_stream_impl_svc_shutdown
};
// clang-format on

#ifdef _POSIX_C_SOURCE
static void io_sock_stream_impl_watch_func(
		struct io_poll_watch *watch, int events);
#endif

static void io_sock_stream_impl_wait_task_func(struct ev_task *task);
#if _WIN32
static void io_sock_stream_impl_wait_cp_func(
		struct io_cp *cp, size_t nbytes, int errc);
#endif

static void io_sock_stream_impl_connect_task_func(struct ev_task *task);
static int io_sock_stream_impl_do_connect(struct io_sock_stream_impl *impl,
		const struct io_sock_stream_handle *handle,
		struct io_sock_stream_connect *connect);
#if _WIN32
static void io_sock_stream_impl_connect_cp_func(
		struct io_cp *cp, size_t nbytes, int errc);
#endif
static void io_sock_stream_impl_connect_post(struct io_sock_stream_impl *impl,
		struct io_sock_stream_connect *connect, int errc);

static void io_sock_stream_impl_recv_task_func(struct ev_task *task);
static void io_sock_stream_impl_recvoob_task_func(struct ev_task *task);
static struct ev_task *io_sock_stream_impl_do_recv_task(
		struct io_sock_stream_impl *impl, struct sllist *recv_queue,
		struct ev_task **pcurrent_recv, int *pwouldblock);
#if _WIN32
static ssize_t io_sock_stream_impl_do_recv(struct io_sock_stream_impl *impl,
		const struct io_sock_stream_handle *handle,
		struct ev_task *task, struct io_cp **pcp);
static void io_sock_stream_impl_recvmsg_cp_func(
		struct io_cp *cp, size_t nbytes, int errc);
static void io_sock_stream_impl_readv_cp_func(
		struct io_cp *cp, size_t nbytes, int errc);
#else
static ssize_t io_sock_stream_impl_do_recv(struct io_sock_stream_impl *impl,
		const struct io_sock_stream_handle *handle,
		struct ev_task *task);
#endif
static void io_sock_stream_impl_recv_post(struct io_sock_stream_impl *impl,
		struct ev_task *task, ssize_t result, int errc);

static void io_sock_stream_impl_send_task_func(struct ev_task *task);
#if _WIN32
static ssize_t io_sock_stream_impl_do_send(struct io_sock_stream_impl *impl,
		const struct io_sock_stream_handle *handle,
		struct ev_task *task, struct io_cp **pcp);
static void io_sock_stream_impl_sendmsg_cp_func(
		struct io_cp *cp, size_t nbytes, int errc);
static void io_sock_stream_impl_writev_cp_func(
		struct io_cp *cp, size_t nbytes, int errc);
#else
static ssize_t io_sock_stream_impl_do_send(struct io_sock_stream_impl *impl,
		const struct io_sock_stream_handle *handle,
		struct ev_task *task);
#endif
static void io_sock_stream_impl_send_post(struct io_sock_stream_impl *impl,
		struct ev_task *task, ssize_t result, int errc);

static inline struct io_sock_stream_impl *io_sock_stream_impl_from_dev(
		const io_dev_t *dev);
static inline struct io_sock_stream_impl *io_sock_stream_impl_from_sock(
		const io_sock_t *sock);
static inline struct io_sock_stream_impl *io_sock_stream_impl_from_stream(
		const io_stream_t *stream);
static inline struct io_sock_stream_impl *io_sock_stream_impl_from_sock_stream(
		const io_sock_stream_t *sock_stream);
static inline struct io_sock_stream_impl *io_sock_stream_impl_from_svc(
		const struct io_svc *svc);

static void io_sock_stream_impl_do_pop(struct io_sock_stream_impl *impl,
		struct sllist *wait_queue, struct sllist *connect_queue,
		struct sllist *recv_queue, struct sllist *send_queue,
		struct ev_task *task);
#if _WIN32
static size_t io_sock_stream_impl_do_cancel_iocp(
		struct io_sock_stream_impl *impl, struct ev_task *task);
#endif
#ifdef _POSIX_C_SOURCE
static int io_sock_stream_impl_do_get_events(struct io_sock_stream_impl *impl);
#endif

static size_t io_sock_stream_do_abort_tasks(struct io_sock_stream_impl *impl);

static SOCKET io_sock_stream_impl_set_handle(struct io_sock_stream_impl *impl,
		const struct io_sock_stream_handle *handle);

int
io_sock_stream_impl_init(struct io_sock_stream_impl *impl, io_poll_t *poll,
		ev_exec_t *exec, const struct io_endp_vtbl *endp_vptr)
{
	assert(impl);
	assert(exec);
	assert(endp_vptr);
	io_ctx_t *ctx = poll ? io_poll_get_ctx(poll) : NULL;

	impl->dev_vptr = &io_sock_stream_impl_dev_vtbl;
	impl->sock_vptr = &io_sock_stream_impl_sock_vtbl;
	impl->stream_vptr = &io_sock_stream_impl_stream_vtbl;
	impl->sock_stream_vptr = &io_sock_stream_impl_vtbl;

	impl->endp_vptr = endp_vptr;

	impl->poll = poll;

	impl->svc = (struct io_svc)IO_SVC_INIT(&io_sock_stream_impl_svc_vtbl);
	impl->ctx = ctx;

	impl->exec = exec;

#ifdef _POSIX_C_SOURCE
	impl->watch = (struct io_poll_watch)IO_POLL_WATCH_INIT(
			&io_sock_stream_impl_watch_func);
#endif

	impl->wait_task = (struct ev_task)EV_TASK_INIT(
			impl->exec, &io_sock_stream_impl_wait_task_func);
	impl->connect_task = (struct ev_task)EV_TASK_INIT(
			impl->exec, &io_sock_stream_impl_connect_task_func);
	impl->recv_task = (struct ev_task)EV_TASK_INIT(
			impl->exec, &io_sock_stream_impl_recv_task_func);
	impl->recvoob_task = (struct ev_task)EV_TASK_INIT(
			impl->exec, &io_sock_stream_impl_recvoob_task_func);
	impl->send_task = (struct ev_task)EV_TASK_INIT(
			impl->exec, &io_sock_stream_impl_send_task_func);

#if !LELY_NO_THREADS
	if (mtx_init(&impl->mtx, mtx_plain) != thrd_success)
		return -1;
#endif
	impl->handle = (struct io_sock_stream_handle)IO_SOCK_STREAM_HANDLE_INIT;

	impl->shutdown = 0;
	impl->wait_posted = 0;
	impl->connect_posted = 0;
	impl->recv_posted = 0;
	impl->recvoob_posted = 0;
	impl->send_posted = 0;

	sllist_init(&impl->wait_queue);
#if _WIN32
	sllist_init(&impl->wait_iocp_queue);
#endif

	sllist_init(&impl->connect_queue);
	impl->current_connect = NULL;
#if _WIN32
	sllist_init(&impl->connect_iocp_queue);
#endif

	sllist_init(&impl->recv_queue);
	impl->current_recv = NULL;
	sllist_init(&impl->recvoob_queue);
	impl->current_recvoob = NULL;
#if _WIN32
	sllist_init(&impl->recv_iocp_queue);
#endif

	sllist_init(&impl->send_queue);
	impl->current_send = NULL;
#if _WIN32
	sllist_init(&impl->send_iocp_queue);
#endif

	if (impl->ctx)
		io_ctx_insert(impl->ctx, &impl->svc);

	return 0;
}

void
io_sock_stream_impl_fini(struct io_sock_stream_impl *impl)
{
	assert(impl);

	if (impl->ctx)
		io_ctx_remove(impl->ctx, &impl->svc);
	// Cancel all pending tasks.
	io_sock_stream_impl_svc_shutdown(&impl->svc);

	// Abort ongoing socket operations.
	if (impl->handle.fd != INVALID_SOCKET)
#if _WIN32
		shutdown(impl->handle.fd, SD_BOTH);
#else
		shutdown(impl->handle.fd, SHUT_RDWR);
#endif

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
	// If necessary, busy-wait until io_sock_stream_impl_wait_task_func(),
	// io_sock_stream_impl_connect_task_func(),
	// io_sock_stream_impl_recv_task_func(),
	// io_sock_stream_impl_recvoob_task_func() and
	// io_sock_stream_impl_send_task_func() complete.
	while (impl->wait_posted || impl->connect_posted || impl->recv_posted
			|| impl->recvoob_posted || impl->send_posted) {
		if (io_sock_stream_do_abort_tasks(impl))
			continue;
		mtx_unlock(&impl->mtx);
		thrd_yield();
		mtx_lock(&impl->mtx);
	}
	mtx_unlock(&impl->mtx);
#endif

	// TODO: Find a reliable way to wait for
	// io_sock_stream_impl_wait_cp_func(),
	// io_sock_stream_impl_connect_cp_func(),
	// io_sock_stream_impl_recvmsg_cp_func(),
	// io_sock_stream_impl_readv_cp_func(),
	// io_sock_stream_impl_sendmsg_cp_func() and
	// io_sock_stream_impl_writev_cp_func() to complete.

	// Close the socket.
	io_sock_stream_impl_sock_close(&impl->sock_vptr);

#if !LELY_NO_THREADS
	mtx_destroy(&impl->mtx);
#endif
}

void
io_sock_stream_impl_get_handle(const struct io_sock_stream_impl *impl,
		struct io_sock_stream_handle *phandle)
{
	assert(impl);

	if (phandle) {
#if !LELY_NO_THREADS
		mtx_lock((mtx_t *)&impl->mtx);
#endif
		*phandle = impl->handle;
#if !LELY_NO_THREADS
		mtx_unlock((mtx_t *)&impl->mtx);
#endif
	}
}

SOCKET
io_sock_stream_impl_open(
		struct io_sock_stream_impl *impl, int family, int protocol)
{
	assert(impl);

	int iError = 0;

#if _WIN32
	SOCKET fd = io_wsa_socket(family, SOCK_STREAM, protocol);
#else
	SOCKET fd = io_fd_socket(family, SOCK_STREAM, protocol);
#endif
	if (fd == INVALID_SOCKET) {
		iError = WSAGetLastError();
		goto error_socket;
	}

	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	handle.fd = fd;
	handle.family = family;
	handle.protocol = protocol;
#if _WIN32
	handle.base = fd;
	// clang-format off
	if (io_sock_fd_init(fd, &handle.base, &handle.family, &handle.protocol,
			&handle.skip_iocp) == -1) {
		// clang-format on
		iError = WSAGetLastError();
		goto error_init;
	}
	// clang-format off
	if (impl->poll && io_poll_register_handle(impl->poll, (HANDLE)fd)
			== -1) {
		// clang-format on
		iError = WSAGetLastError();
		goto error_init;
	}
#endif
	fd = io_sock_stream_impl_set_handle(impl, &handle);
	if (fd != INVALID_SOCKET)
		closesocket(fd);

	return handle.fd;

#if _WIN32
error_init:
#endif
	closesocket(fd);
error_socket:
	WSASetLastError(iError);
	return -1;
}

int
io_sock_stream_impl_assign(struct io_sock_stream_impl *impl,
		const struct io_sock_stream_handle *handle)
{
	assert(impl);
	assert(handle);

	SOCKET fd = handle->fd;
#if _WIN32
	if (io_wsa_set_nonblock(fd) == -1)
		return -1;
	struct io_sock_stream_handle handle_ = *handle;
	handle = &handle_;
	// clang-format off
	if (io_sock_fd_init(fd, &handle_.base, &handle_.family,
			&handle_.protocol, &handle_.skip_iocp) == -1)
		// clang-format on
		return -1;
	if (impl->poll && io_poll_register_handle(impl->poll, (HANDLE)fd) == -1)
		return -1;
#elif defined(_POSIX_C_SOURCE)
	if (io_fd_set_nonblock(fd) == -1)
		return -1;

#endif
	fd = io_sock_stream_impl_set_handle(impl, handle);
	if (fd != INVALID_SOCKET)
		closesocket(fd);

	return 0;
}

SOCKET
io_sock_stream_impl_release(struct io_sock_stream_impl *impl)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	return io_sock_stream_impl_set_handle(impl, &handle);
}

static io_ctx_t *
io_sock_stream_impl_dev_get_ctx(const io_dev_t *dev)
{
	const struct io_sock_stream_impl *impl =
			io_sock_stream_impl_from_dev(dev);

	return impl->ctx;
}

static ev_exec_t *
io_sock_stream_impl_dev_get_exec(const io_dev_t *dev)
{
	const struct io_sock_stream_impl *impl =
			io_sock_stream_impl_from_dev(dev);

	return impl->exec;
}

static size_t
io_sock_stream_impl_dev_cancel(io_dev_t *dev, struct ev_task *task)
{
	struct io_sock_stream_impl *impl = io_sock_stream_impl_from_dev(dev);

	size_t n = 0;

	struct sllist wait_queue, connect_queue, recv_queue, send_queue;
	sllist_init(&wait_queue);
	sllist_init(&connect_queue);
	sllist_init(&recv_queue);
	sllist_init(&send_queue);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	io_sock_stream_impl_do_pop(impl, &wait_queue, &connect_queue,
			&recv_queue, &send_queue, task);
#if _WIN32
	// Cancel operations waiting for a completion packet.
	n = io_sock_stream_impl_do_cancel_iocp(impl, task);
#endif
	// Mark the ongoing receive operations as canceled, if necessary.
	if (impl->current_recv && (!task || task == impl->current_recv)) {
		impl->current_recv = NULL;
		n += n < SIZE_MAX;
	}
	if (impl->current_recvoob && (!task || task == impl->current_recvoob)) {
		impl->current_recvoob = NULL;
		n += n < SIZE_MAX;
	}
	// Mark the ongoing send operation as canceled, if necessary.
	if (impl->current_send && (!task || task == impl->current_send)) {
		impl->current_send = NULL;
		n += n < SIZE_MAX;
	}
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif

	size_t nwait = io_sock_wait_queue_post(
			&wait_queue, IO_EVENT_ERR, ERROR_OPERATION_ABORTED);
	n = n < SIZE_MAX - nwait ? n + nwait : SIZE_MAX;
	size_t nconnect = io_sock_stream_connect_queue_post(
			&connect_queue, ERROR_OPERATION_ABORTED);
	n = n < SIZE_MAX - nconnect ? n + nconnect : SIZE_MAX;
	size_t nrecvmsg = io_sock_stream_recv_queue_post(
			&recv_queue, -1, ERROR_OPERATION_ABORTED);
	n = n < SIZE_MAX - nrecvmsg ? n + nrecvmsg : SIZE_MAX;
	size_t nsendmsg = io_sock_stream_send_queue_post(
			&send_queue, -1, ERROR_OPERATION_ABORTED);
	n = n < SIZE_MAX - nsendmsg ? n + nsendmsg : SIZE_MAX;

	return n;
}

static size_t
io_sock_stream_impl_dev_abort(io_dev_t *dev, struct ev_task *task)
{
	struct io_sock_stream_impl *impl = io_sock_stream_impl_from_dev(dev);

	struct sllist queue;
	sllist_init(&queue);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	io_sock_stream_impl_do_pop(impl, &queue, &queue, &queue, &queue, task);
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif

	return ev_task_queue_abort(&queue);
}

static io_dev_t *
io_sock_stream_impl_sock_get_dev(const io_sock_t *sock)
{
	const struct io_sock_stream_impl *impl =
			io_sock_stream_impl_from_sock(sock);

	return &impl->dev_vptr;
}

static int
io_sock_stream_impl_sock_bind(
		io_sock_t *sock, const struct io_endp *endp, int reuseaddr)
{
	struct io_sock_stream_impl *impl = io_sock_stream_impl_from_sock(sock);
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(impl, &handle);

	return io_sock_fd_bind(handle.fd, handle.family, handle.protocol,
			impl->endp_vptr, endp, reuseaddr);
}

static int
io_sock_stream_impl_sock_getsockname(
		const io_sock_t *sock, struct io_endp *endp)
{
	const struct io_sock_stream_impl *impl =
			io_sock_stream_impl_from_sock(sock);
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(impl, &handle);

	return io_sock_fd_getsockname(handle.fd, impl->endp_vptr, endp);
}

static int
io_sock_stream_impl_sock_is_open(const io_sock_t *sock)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_sock(sock), &handle);

	return handle.fd != INVALID_SOCKET;
}

static int
io_sock_stream_impl_sock_close(io_sock_t *sock)
{
	struct io_sock_stream_impl *impl = io_sock_stream_impl_from_sock(sock);

	SOCKET fd = io_sock_stream_impl_release(impl);
	return fd != INVALID_SOCKET ? (!closesocket(fd) ? 0 : -1) : 0;
}

static int
io_sock_stream_impl_sock_wait(io_sock_t *sock, int *events, int timeout)
{
	struct io_sock_stream_impl *impl = io_sock_stream_impl_from_sock(sock);

	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(impl, &handle);

#if _WIN32
	if (impl->poll)
		return io_poll_afd(impl->poll, (HANDLE)handle.base, events,
				timeout);
#endif
	return io_sock_fd_wait(handle.fd, events, timeout);
}

static void
io_sock_stream_impl_sock_submit_wait(io_sock_t *sock, struct io_sock_wait *wait)
{
	struct io_sock_stream_impl *impl = io_sock_stream_impl_from_sock(sock);
	assert(wait);
	struct ev_task *task = &wait->task;

	if (!task->exec)
		task->exec = impl->exec;
	ev_exec_on_task_init(task->exec);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	if (impl->shutdown) {
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		io_sock_wait_post(wait, IO_EVENT_ERR, ERROR_OPERATION_ABORTED);
	} else {
		int post_wait = !impl->wait_posted
				&& sllist_empty(&impl->wait_queue);
		sllist_push_back(&impl->wait_queue, &task->_node);
		if (post_wait)
			impl->wait_posted = 1;
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		if (post_wait)
			ev_exec_post(impl->wait_task.exec, &impl->wait_task);
	}
}

static int
io_sock_stream_impl_sock_get_error(io_sock_t *sock)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_sock(sock), &handle);

	return io_sock_fd_get_error(handle.fd);
}

static int
io_sock_stream_impl_sock_get_nread(const io_sock_t *sock)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_sock(sock), &handle);

	return io_sock_fd_get_nread(handle.fd);
}

static int
io_sock_stream_impl_sock_get_dontroute(const io_sock_t *sock)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_sock(sock), &handle);

	return io_sock_fd_get_dontroute(handle.fd);
}

static int
io_sock_stream_impl_sock_set_dontroute(io_sock_t *sock, int optval)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_sock(sock), &handle);

	return io_sock_fd_set_dontroute(handle.fd, optval);
}

static int
io_sock_stream_impl_sock_get_rcvbuf(const io_sock_t *sock)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_sock(sock), &handle);

	return io_sock_fd_get_rcvbuf(handle.fd);
}

static int
io_sock_stream_impl_sock_set_rcvbuf(io_sock_t *sock, int optval)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_sock(sock), &handle);

	return io_sock_fd_set_rcvbuf(handle.fd, optval);
}

static int
io_sock_stream_impl_sock_get_sndbuf(const io_sock_t *sock)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_sock(sock), &handle);

	return io_sock_fd_get_sndbuf(handle.fd);
}

static int
io_sock_stream_impl_sock_set_sndbuf(io_sock_t *sock, int optval)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_sock(sock), &handle);

	return io_sock_fd_set_sndbuf(handle.fd, optval);
}

static io_dev_t *
io_sock_stream_impl_stream_get_dev(const io_stream_t *stream)
{
	const struct io_sock_stream_impl *impl =
			io_sock_stream_impl_from_stream(stream);

	return &impl->dev_vptr;
}

static ssize_t
io_sock_stream_impl_stream_readv(
		io_stream_t *stream, const struct io_buf *buf, int bufcnt)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_stream(stream), &handle);

	int flags = 0;
	return io_sock_fd_recvmsg(
			handle.fd, buf, bufcnt, &flags, NULL, NULL, -1);
}

static void
io_sock_stream_impl_stream_submit_readv(
		io_stream_t *stream, struct io_stream_readv *readv)
{
	struct io_sock_stream_impl *impl =
			io_sock_stream_impl_from_stream(stream);
	assert(readv);
	struct ev_task *task = &readv->task;

	if (!task->exec)
		task->exec = impl->exec;
	ev_exec_on_task_init(task->exec);
	readv->task._data = NULL;

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	if (impl->shutdown) {
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		io_stream_readv_post(readv, -1, ERROR_OPERATION_ABORTED);
	} else if (readv->bufcnt <= 0) {
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		io_stream_readv_post(readv, -1, WSAEINVAL);
	} else {
		int post_recv = !impl->recv_posted
				&& sllist_empty(&impl->recv_queue);
		sllist_push_back(&impl->recv_queue, &task->_node);
		if (post_recv)
			impl->recv_posted = 1;
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		if (post_recv)
			ev_exec_post(impl->recv_task.exec, &impl->recv_task);
	}
}

static ssize_t
io_sock_stream_impl_stream_writev(
		io_stream_t *stream, const struct io_buf *buf, int bufcnt)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_stream(stream), &handle);

	return io_sock_fd_sendmsg(handle.fd, buf, bufcnt, 0, NULL, NULL, -1);
}

static void
io_sock_stream_impl_stream_submit_writev(
		io_stream_t *stream, struct io_stream_writev *writev)
{
	struct io_sock_stream_impl *impl =
			io_sock_stream_impl_from_stream(stream);
	assert(writev);
	struct ev_task *task = &writev->task;

	if (!task->exec)
		task->exec = impl->exec;
	ev_exec_on_task_init(task->exec);
	writev->task._data = NULL;

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	if (impl->shutdown) {
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		io_stream_writev_post(writev, -1, ERROR_OPERATION_ABORTED);
	} else if (writev->bufcnt <= 0) {
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		io_stream_writev_post(writev, -1, WSAEINVAL);
	} else {
		int post_send = !impl->send_posted
				&& sllist_empty(&impl->send_queue);
		sllist_push_back(&impl->send_queue, &task->_node);
		if (post_send)
			impl->send_posted = 1;
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		if (post_send)
			ev_exec_post(impl->send_task.exec, &impl->send_task);
	}
}

static io_sock_t *
io_sock_stream_impl_get_sock(const io_sock_stream_t *sock)
{
	const struct io_sock_stream_impl *impl =
			io_sock_stream_impl_from_sock_stream(sock);

	return &impl->sock_vptr;
}

static io_stream_t *
io_sock_stream_impl_get_stream(const io_sock_stream_t *sock)
{
	const struct io_sock_stream_impl *impl =
			io_sock_stream_impl_from_sock_stream(sock);

	return &impl->stream_vptr;
}

static int
io_sock_stream_impl_connect(io_sock_stream_t *sock, const struct io_endp *endp)
{
	struct io_sock_stream_impl *impl =
			io_sock_stream_impl_from_sock_stream(sock);
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(impl, &handle);

	return io_sock_fd_connect(handle.fd, impl->endp_vptr, endp, 0);
}

static void
io_sock_stream_impl_submit_connect(
		io_sock_stream_t *sock, struct io_sock_stream_connect *connect)
{
	struct io_sock_stream_impl *impl =
			io_sock_stream_impl_from_sock_stream(sock);
	assert(connect);
	struct ev_task *task = &connect->task;

	if (!task->exec)
		task->exec = impl->exec;
	ev_exec_on_task_init(task->exec);
	connect->task._data = NULL;

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	if (impl->shutdown) {
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		io_sock_stream_connect_post(connect, ERROR_OPERATION_ABORTED);
	} else {
		int post_connect = !impl->connect_posted
				&& sllist_empty(&impl->connect_queue);
		sllist_push_back(&impl->connect_queue, &task->_node);
		if (post_connect)
			impl->connect_posted = 1;
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		if (post_connect)
			ev_exec_post(impl->connect_task.exec,
					&impl->connect_task);
	}
}

static int
io_sock_stream_impl_getpeername(
		const io_sock_stream_t *sock, struct io_endp *endp)
{
	const struct io_sock_stream_impl *impl =
			io_sock_stream_impl_from_sock_stream(sock);
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(impl, &handle);

	return io_sock_fd_getpeername(handle.fd, impl->endp_vptr, endp);
}

static ssize_t
io_sock_stream_impl_recvmsg(io_sock_stream_t *sock, const struct io_buf *buf,
		int bufcnt, int *flags, int timeout)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_sock_stream(sock), &handle);

	return io_sock_fd_recvmsg(
			handle.fd, buf, bufcnt, flags, NULL, NULL, timeout);
}

static void
io_sock_stream_impl_submit_recvmsg(
		io_sock_stream_t *sock, struct io_sock_stream_recvmsg *recvmsg)
{
	struct io_sock_stream_impl *impl =
			io_sock_stream_impl_from_sock_stream(sock);
	assert(recvmsg);
	struct ev_task *task = &recvmsg->task;

	if (!task->exec)
		task->exec = impl->exec;
	ev_exec_on_task_init(task->exec);
	recvmsg->task._data = (void *)(uintptr_t)1;

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	if (impl->shutdown) {
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		io_sock_stream_recvmsg_post(
				recvmsg, -1, ERROR_OPERATION_ABORTED);
	} else if (recvmsg->bufcnt <= 0) {
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		io_sock_stream_recvmsg_post(recvmsg, -1, WSAEINVAL);
	} else if (recvmsg->flags & IO_MSG_OOB) {
		int post_recvoob = !impl->recvoob_posted
				&& sllist_empty(&impl->recvoob_queue);
		sllist_push_back(&impl->recvoob_queue, &task->_node);
		if (post_recvoob)
			impl->recvoob_posted = 1;
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		if (post_recvoob)
			ev_exec_post(impl->recvoob_task.exec,
					&impl->recvoob_task);
	} else {
		int post_recv = !impl->recv_posted
				&& sllist_empty(&impl->recv_queue);
		sllist_push_back(&impl->recv_queue, &task->_node);
		if (post_recv)
			impl->recv_posted = 1;
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		if (post_recv)
			ev_exec_post(impl->recv_task.exec, &impl->recv_task);
	}
}

static ssize_t
io_sock_stream_impl_sendmsg(io_sock_stream_t *sock, const struct io_buf *buf,
		int bufcnt, int flags, int timeout)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_sock_stream(sock), &handle);

	return io_sock_fd_sendmsg(
			handle.fd, buf, bufcnt, flags, NULL, NULL, timeout);
}

static void
io_sock_stream_impl_submit_sendmsg(
		io_sock_stream_t *sock, struct io_sock_stream_sendmsg *sendmsg)
{
	struct io_sock_stream_impl *impl =
			io_sock_stream_impl_from_sock_stream(sock);
	assert(sendmsg);
	struct ev_task *task = &sendmsg->task;

	if (!task->exec)
		task->exec = impl->exec;
	ev_exec_on_task_init(task->exec);
	sendmsg->task._data = (void *)(uintptr_t)1;

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	if (impl->shutdown) {
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		io_sock_stream_sendmsg_post(
				sendmsg, -1, ERROR_OPERATION_ABORTED);
	} else if (sendmsg->bufcnt <= 0) {
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		io_sock_stream_sendmsg_post(sendmsg, -1, WSAEINVAL);
	} else {
		int post_send = !impl->send_posted
				&& sllist_empty(&impl->send_queue);
		sllist_push_back(&impl->send_queue, &task->_node);
		if (post_send)
			impl->send_posted = 1;
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		if (post_send)
			ev_exec_post(impl->send_task.exec, &impl->send_task);
	}
}

static int
io_sock_stream_impl_shutdown(io_sock_stream_t *sock, int type)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_sock_stream(sock), &handle);

	int how;
	switch (type) {
	case IO_SHUT_RD: how = SD_RECEIVE; break;
	case IO_SHUT_WR: how = SD_SEND; break;
	case IO_SHUT_RDWR: how = SD_BOTH; break;
	default: WSASetLastError(WSAEINVAL); return -1;
	}

	return !shutdown(handle.fd, how) ? 0 : -1;
}

static int
io_sock_stream_impl_get_keepalive(const io_sock_stream_t *sock)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_sock_stream(sock), &handle);

	int optval = 0;
	// clang-format off
	if (getsockopt(handle.fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&optval,
			&(socklen_t){ sizeof(optval) }) == SOCKET_ERROR)
		// clang-format on
		return -1;
	return optval;
}

static int
io_sock_stream_impl_set_keepalive(io_sock_stream_t *sock, int optval)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_sock_stream(sock), &handle);

	// clang-format off
	return !setsockopt(handle.fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&optval,
			sizeof(optval)) ? 0 : -1;
	// clang-format on
}

static int
io_sock_stream_impl_get_linger(
		const io_sock_stream_t *sock, int *ponoff, int *plinger)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_sock_stream(sock), &handle);

	struct linger optval = { .l_onoff = 0 };
	// clang-format off
	if (getsockopt(handle.fd, SOL_SOCKET, SO_LINGER, (void *)&optval,
			&(socklen_t){ sizeof(optval) }) == SOCKET_ERROR)
		// clang-format on
		return -1;

	if (ponoff)
		*ponoff = optval.l_onoff;

	if (plinger)
		*plinger = optval.l_onoff ? optval.l_linger : 0;

	return 0;
}

static int
io_sock_stream_impl_set_linger(io_sock_stream_t *sock, int onoff, int linger)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_sock_stream(sock), &handle);

#if _WIN32
	if (onoff && (linger < 0 || linger > USHRT_MAX)) {
		WSASetLastError(WSAEINVAL);
		return -1;
	}
#endif

	struct linger optval = { .l_onoff = !!onoff,
		.l_linger = onoff ? linger : 0 };
	// clang-format off
	return !setsockopt(handle.fd, SOL_SOCKET, SO_LINGER, (void *)&optval,
			sizeof(optval)) ? 0 : -1;
	// clang-format on
}

static int
io_sock_stream_impl_get_oobinline(const io_sock_stream_t *sock)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_sock_stream(sock), &handle);

	int optval = 0;
	// clang-format off
	if (getsockopt(handle.fd, SOL_SOCKET, SO_OOBINLINE, (void *)&optval,
			&(socklen_t){ sizeof(optval) }) == SOCKET_ERROR)
		// clang-format on
		return -1;
	return optval;
}

static int
io_sock_stream_impl_set_oobinline(io_sock_stream_t *sock, int optval)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_sock_stream(sock), &handle);

	// clang-format off
	return !setsockopt(handle.fd, SOL_SOCKET, SO_OOBINLINE, (void *)&optval,
			sizeof(optval)) ? 0 : -1;
	// clang-format on
}

static int
io_sock_stream_impl_atmark(const io_sock_stream_t *sock)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_sock_stream(sock), &handle);

#if _WIN32
	u_long arg = 0;
	return !ioctlsocket(handle.fd, SIOCATMARK, &arg) ? arg != 0 : -1;
#else
	return sockatmark(handle.fd);
#endif
}

static void
io_sock_stream_impl_svc_shutdown(struct io_svc *svc)
{
	struct io_sock_stream_impl *impl = io_sock_stream_impl_from_svc(svc);
	io_dev_t *dev = &impl->dev_vptr;

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	int shutdown = !impl->shutdown;
	impl->shutdown = 1;
	if (shutdown) {
#ifdef _POSIX_C_SOURCE
		if (impl->poll && impl->handle.fd != -1)
			// Stop monitoring I/O events.
			io_poll_watch(impl->poll, impl->handle.fd, 0,
					&impl->watch);
#endif // _POSIX_C_SOURCE

		// Try to abort io_sock_stream_impl_connect_task_func(),
		// io_sock_stream_impl_wait_task_func(),
		// io_sock_stream_impl_recv_task_func(),
		// io_sock_stream_impl_recvoob_task_func() and
		// io_sock_stream_impl_send_task_func().
		io_sock_stream_do_abort_tasks(impl);
	}
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif

	if (shutdown)
		// Cancel all pending operations.
		io_sock_stream_impl_dev_cancel(dev, NULL);
}

#ifdef _POSIX_C_SOURCE
static void
io_sock_stream_impl_watch_func(struct io_poll_watch *watch, int events)
{
	assert(watch);
	struct io_sock_stream_impl *impl =
			structof(watch, struct io_sock_stream_impl, watch);

	struct sllist wait_queue;
	sllist_init(&wait_queue);
	struct ev_task *connect_task = NULL;
	struct ev_task *recv_task = NULL;
	struct ev_task *recvoob_task = NULL;
	struct ev_task *send_task = NULL;

	int errc = 0;
	if (events & IO_EVENT_ERR)
		errc = io_sock_get_error(&impl->sock_vptr);
	int mask = 0;

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	// Report a socket error to all pending wait operations and the first
	// pending send and receive operations.
	io_sock_wait_queue_select(&wait_queue, &impl->wait_queue, events, errc);
	if (errc) {
		recv_task = ev_task_from_node(
				sllist_pop_front(&impl->recv_queue));
		recvoob_task = ev_task_from_node(
				sllist_pop_front(&impl->recvoob_queue));
		send_task = ev_task_from_node(
				sllist_pop_front(&impl->send_queue));
	}

	// Process the pending connect operation.
	int post_connect = 0;
	mask = IO_EVENT_OUT | IO_EVENT_ERR | IO_EVENT_HUP;
	if ((events & mask) && !sllist_empty(&impl->connect_queue)) {
		connect_task = ev_task_from_node(
				sllist_first(&impl->connect_queue));
		if (connect_task == impl->current_connect) {
			sllist_pop_front(&impl->connect_queue);
			impl->current_connect = NULL;
		} else {
			connect_task = NULL;
		}
		assert(!impl->current_connect);

		if (!sllist_empty(&impl->connect_queue) && !impl->shutdown) {
			post_connect = !impl->connect_posted;
			impl->connect_posted = 1;
		}
	}

	// Retry any pending receive operations.
	int post_recv = 0;
	mask = IO_EVENT_IN | IO_EVENT_ERR | IO_EVENT_HUP;
	if ((events & mask) && !sllist_empty(&impl->recv_queue)
			&& !impl->shutdown) {
		post_recv = !impl->recv_posted;
		impl->recv_posted = 1;
	}

	int post_recvoob = 0;
	mask = IO_EVENT_PRI | IO_EVENT_ERR | IO_EVENT_HUP;
	if ((events & mask) && !sllist_empty(&impl->recvoob_queue)
			&& !impl->shutdown) {
		post_recvoob = !impl->recvoob_posted;
		impl->recvoob_posted = 1;
	}

	// Retry any pending send operations.
	int post_send = 0;
	mask = IO_EVENT_OUT | IO_EVENT_ERR | IO_EVENT_HUP;
	if ((events & mask) && !sllist_empty(&impl->send_queue)
			&& !impl->shutdown) {
		post_send = !impl->send_posted;
		impl->send_posted = 1;
	}
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif

	io_sock_wait_queue_post(&wait_queue, events, errc);

	if (connect_task) {
		struct io_sock_stream_connect *connect =
				io_sock_stream_connect_from_task(connect_task);
		io_sock_stream_impl_connect_post(impl, connect, errc);
	}

	if (recv_task)
		io_sock_stream_recv_post(recv_task, -1, errc);

	if (recvoob_task)
		io_sock_stream_recv_post(recvoob_task, -1, errc);

	if (send_task)
		io_sock_stream_send_post(send_task, -1, errc);

	if (post_connect)
		ev_exec_post(impl->connect_task.exec, &impl->connect_task);
	if (post_recv)
		ev_exec_post(impl->recv_task.exec, &impl->recv_task);
	if (post_recvoob)
		ev_exec_post(impl->recvoob_task.exec, &impl->recvoob_task);
	if (post_send)
		ev_exec_post(impl->send_task.exec, &impl->send_task);
}
#endif // _POSIX_C_SOURCE

static void
io_sock_stream_impl_wait_task_func(struct ev_task *task)
{
	assert(task);
	struct io_sock_stream_impl *impl =
			structof(task, struct io_sock_stream_impl, wait_task);

	int iError = WSAGetLastError();

	struct sllist wait_queue;
	sllist_init(&wait_queue);
	int events = 0;
	int errc = 0;

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	int post_wait = 0;
	if (impl->poll) {
#if _WIN32
		/// Try to process all pending wait operations at once.
		while ((task = ev_task_from_node(
					sllist_pop_front(&impl->wait_queue)))) {
			// Move the operation to the I/O completion port queue.
			sllist_push_back(&impl->wait_iocp_queue, &task->_node);
			struct io_sock_wait *wait =
					io_sock_wait_from_task(task);
			wait->task._data = impl;
			// Perform the polling operation without holding the
			// mutex.
			SOCKET fd = impl->handle.base;
#if !LELY_NO_THREADS
			mtx_unlock(&impl->mtx);
#endif
			wait->_info = (AFD_POLL_INFO){
				.Timeout.QuadPart = LLONG_MAX,
				.NumberOfHandles = 1,
				.Exclusive = FALSE,
				.Handles[0] = { .Handle = (HANDLE)fd,
						.Events = io_event_to_afd_poll(
								wait->events) }
			};
			wait->_cp = (struct io_cp)IO_CP_INIT(
					&io_sock_stream_impl_wait_cp_func);
			int result = io_poll_submit_afd(
					impl->poll, &wait->_info, &wait->_cp);
			errc = !result ? 0 : GetLastError();
#if !LELY_NO_THREADS
			mtx_lock(&impl->mtx);
#endif
			if (errc) {
				// If an error occurred when submitting the AFD
				// poll operation, no completion packet will be
				// posted.
				sllist_remove(&impl->wait_iocp_queue,
						&task->_node);
				sllist_push_back(&wait_queue, &task->_node);
				break;
			}
		}
		impl->wait_posted = 0;
		post_wait = !sllist_empty(&impl->wait_queue) && !impl->shutdown;
#else
		impl->wait_posted = 0;
		events = io_sock_stream_impl_do_get_events(impl);
		// Start watching the file descriptor for the monitored events.
		if (events && impl->handle.fd != -1 && !impl->shutdown)
			io_poll_watch(impl->poll, impl->handle.fd, events,
					&impl->watch);
#endif
	} else {
		// Obtain the union of all monitored I/O events.
		sllist_foreach (&impl->wait_queue, node) {
			struct io_sock_wait *wait = io_sock_wait_from_task(
					ev_task_from_node(node));
			events |= wait->events;
		}

		SOCKET fd = impl->handle.fd;
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		// Perform a blocking wait.
		int result = io_sock_fd_wait(fd, &events, LELY_IO_RX_TIMEOUT);
		errc = !result ? 0 : WSAGetLastError();
		int wouldblock = errc == WSAEAGAIN || errc == WSAEWOULDBLOCK;
#if !LELY_NO_THREADS
		mtx_lock(&impl->mtx);
#endif
		// If no timeout occurred, select the wait operations matching
		// the reported event (or all on error).
		if (!wouldblock)
			io_sock_wait_queue_select(&wait_queue,
					&impl->wait_queue, events, errc);
		impl->wait_posted = 0;
		post_wait = !sllist_empty(&impl->wait_queue) && !impl->shutdown;
	}
	if (post_wait)
		impl->wait_posted = 1;
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif

	// Post completed blocking wait operations or failed AFD polling
	// operations.
	io_sock_wait_queue_post(&wait_queue, events, errc);

	if (post_wait)
		ev_exec_post(impl->wait_task.exec, &impl->wait_task);

	WSASetLastError(iError);
}

#if _WIN32
static void
io_sock_stream_impl_wait_cp_func(struct io_cp *cp, size_t nbytes, int errc)
{
	assert(cp);
	struct io_sock_wait *wait = structof(cp, struct io_sock_wait, _cp);
	(void)nbytes;

	// Remove the task from the queue, unless it was canceled.
	if (wait->task._data && errc != ERROR_OPERATION_ABORTED) {
		struct io_sock_stream_impl *impl = wait->task._data;
		assert(impl->poll);
#if !LELY_NO_THREADS
		mtx_lock(&impl->mtx);
#endif
		sllist_remove(&impl->wait_iocp_queue, &wait->task._node);
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
	}
	wait->task._data = NULL;

	int events = 0;
	if (!errc && wait->_info.NumberOfHandles)
		events = io_afd_poll_to_event(wait->_info.Handles[0].Events);
	io_sock_wait_post(wait, events, errc);
}
#endif // _WIN32

static void
io_sock_stream_impl_connect_task_func(struct ev_task *task)
{
	assert(task);
	struct io_sock_stream_impl *impl = structof(
			task, struct io_sock_stream_impl, connect_task);

	int iError = WSAGetLastError();

	struct io_sock_stream_connect *connect = NULL;
	int errc = 0;
	int inprogress = 0;

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	task = NULL;
	if (impl->current_connect)
		// Do not interrupt a connection in progress.
		inprogress = 1;
	else
		// Obtain the first connection operation, but leave it on the
		// queue.
		task = ev_task_from_node(sllist_first(&impl->connect_queue));
	if (task) {
		connect = io_sock_stream_connect_from_task(task);
#if _WIN32
		if ((task->_data = impl->poll ? impl : NULL)) {
			// Move the task to the I/O completion port queue.
			sllist_pop_front(&impl->connect_queue);
			sllist_push_back(&impl->connect_iocp_queue,
					&task->_node);
		} else
#endif
			impl->current_connect = task;
		struct io_sock_stream_handle handle = impl->handle;
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		int result = io_sock_stream_impl_do_connect(
				impl, &handle, connect);
		errc = !result ? 0 : WSAGetLastError();
#if _WIN32
		if (impl->poll && !errc && handle.skip_iocp)
			// The operation completed synchronously. If possible,
			// skip the I/O completion packet.
			io_sock_stream_impl_connect_cp_func(
					&connect->_cp, result, errc);
		inprogress = impl->poll && (!errc || errc == ERROR_IO_PENDING);
#else
		inprogress = errc == EINPROGRESS || errc == EINTR;
#endif
#if !LELY_NO_THREADS
		mtx_lock(&impl->mtx);
#endif
#if _WIN32
		if (!impl->poll) {
#endif
			task = ev_task_from_node(
					sllist_first(&impl->connect_queue));
			if (task != impl->current_connect) {
				// If the operation was canceled, we do not
				// consider it to be in progress and do not need
				// to post the completion task.
				inprogress = 0;
				task = NULL;
			} else if (!inprogress)
				// If the connection was established
				// synchronously, remove it from the queue.
				sllist_pop_front(&impl->connect_queue);
			assert(!task || task == &connect->task);
#if _WIN32
		}
#endif
		if (inprogress)
			task = NULL;
		else
			impl->current_connect = NULL;
	}
#ifdef _POSIX_C_SOURCE
	// If the connection is in progress (and the socket has not been closed
	// in the mean time), start watching the file descriptor.
	if (impl->poll && inprogress && impl->handle.fd != -1
			&& !impl->shutdown) {
		int events = io_sock_stream_impl_do_get_events(impl);
		io_poll_watch(impl->poll, impl->handle.fd, events,
				&impl->watch);
	}
#endif
#if _WIN32
	int watch = 0;
#else
	int watch = impl->poll && inprogress;
#endif
	int post_connect = impl->connect_posted =
			!sllist_empty(&impl->connect_queue) && !watch
			&& !impl->shutdown;
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif

	if (task) {
		connect = io_sock_stream_connect_from_task(task);
		io_sock_stream_impl_connect_post(impl, connect, errc);
	}

	if (post_connect)
		ev_exec_post(impl->connect_task.exec, &impl->connect_task);

	WSASetLastError(iError);
}

static int
io_sock_stream_impl_do_connect(struct io_sock_stream_impl *impl,
		const struct io_sock_stream_handle *handle,
		struct io_sock_stream_connect *connect)
{
	assert(impl);
	assert(impl->endp_vptr);
	assert(impl->endp_vptr->store);
	assert(handle);
	assert(connect);

#if _WIN32
	if (!impl->poll)
#endif
		return io_sock_fd_connect(handle->fd, impl->endp_vptr,
				connect->endp, impl->poll != NULL);

#if _WIN32
	connect->_handle = (HANDLE)handle->fd;
	connect->_cp = (struct io_cp)IO_CP_INIT(
			&io_sock_stream_impl_connect_cp_func);

	struct sockaddr_storage name = { .ss_family = AF_UNSPEC };
	int namelen = sizeof(name);

	// Check if socket is already bound.
	int bound = 0;
	if (!getsockname(handle->fd, (struct sockaddr *)&name, &namelen))
		bound = name.ss_family != AF_UNSPEC;
	// ConnectEx() does not bind an unboud socket, so we bind it here.
	// clang-format off
	if (!bound && io_sock_fd_bind(handle->fd, handle->family,
			handle->protocol, impl->endp_vptr, NULL, 0) == -1)
		// clang-format on
		return -1;

	name = (struct sockaddr_storage){ .ss_family = AF_UNSPEC };
	namelen = sizeof(name);
	if (connect->endp) {
		// clang-format off
			if (impl->endp_vptr->store(connect->endp,
					(struct sockaddr *)&name, &namelen)
					== -1)
			// clang-format on
			return -1;
	} else {
		namelen = sizeof(struct sockaddr);
	}

	if (!handle->lpfnConnectEx) {
		WSASetLastError(WSAEOPNOTSUPP);
		return -1;
	}

	DWORD dwBytesSent = 0;
	// clang-format off
	if (!handle->lpfnConnectEx(handle->fd, (const struct sockaddr *)&name,
			namelen, NULL, 0, &dwBytesSent,
			&connect->_cp.overlapped))
		// clang-format on
		return -1;

	return 0;
#endif
}

#if _WIN32
static void
io_sock_stream_impl_connect_cp_func(struct io_cp *cp, size_t nbytes, int errc)
{
	assert(cp);
	struct io_sock_stream_connect *connect =
			structof(cp, struct io_sock_stream_connect, _cp);
	struct io_sock_stream_impl *impl = connect->task._data;
	connect->task._data = NULL;
	(void)nbytes;

	SOCKET s = (SOCKET)connect->_handle;

	if (!errc) {
		int iError = WSAGetLastError();
		// clang-format off
		if (setsockopt(s, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL,
				0) == SOCKET_ERROR) {
			// clang-format on
			errc = WSAGetLastError();
			WSASetLastError(iError);
		}
	}

	io_sock_stream_impl_connect_post(impl, connect, errc);
}
#endif // _WIN32

static void
io_sock_stream_impl_connect_post(struct io_sock_stream_impl *impl,
		struct io_sock_stream_connect *connect, int errc)
{
	assert(impl);
	assert(connect);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
#if _WIN32
	if (impl->poll && errc != ERROR_OPERATION_ABORTED)
		sllist_remove(&impl->connect_iocp_queue, &connect->task._node);
#endif
	int post_connect = impl->connect_posted =
			!sllist_empty(&impl->connect_queue);
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif

	io_sock_stream_connect_post(connect, errc);

	if (post_connect)
		ev_exec_post(impl->connect_task.exec, &impl->connect_task);
}

static void
io_sock_stream_impl_recv_task_func(struct ev_task *task)
{
	assert(task);
	struct io_sock_stream_impl *impl =
			structof(task, struct io_sock_stream_impl, recv_task);

	int iError = WSAGetLastError();

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	// Process as many receive operations as possible. During the I/O
	// operation, the mutex will be unlocked.
	int wouldblock = 0;
	task = io_sock_stream_impl_do_recv_task(impl, &impl->recv_queue,
			&impl->current_recv, &wouldblock);
	impl->recv_posted = 0;
#ifdef _POSIX_C_SOURCE
	// If the operation would block (and the socket has not been closed in
	// the mean time), start watching the file descriptor.
	if (impl->poll && wouldblock && !sllist_empty(&impl->recv_queue)
			&& impl->handle.fd != -1 && !impl->shutdown) {
		int events = io_sock_stream_impl_do_get_events(impl);
		io_poll_watch(impl->poll, impl->handle.fd, events,
				&impl->watch);
	}
#endif
	// Repost this task if any receive operations remain in the queue,
	// unless we're waiting the file descriptor to become ready (which we
	// never do on Windows).
#if _WIN32
	int watch = 0;
#else
	int watch = impl->poll && wouldblock;
#endif
	int post_recv = !sllist_empty(&impl->recv_queue) && !watch
			&& !impl->shutdown;
	if (post_recv)
		impl->recv_posted = 1;
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif

	if (task && wouldblock)
		// The operation would block but was canceled before it could be
		// requeued.
		io_sock_stream_recv_post(task, -1, ERROR_OPERATION_ABORTED);

	if (post_recv)
		ev_exec_post(impl->recv_task.exec, &impl->recv_task);

	WSASetLastError(iError);
}

static void
io_sock_stream_impl_recvoob_task_func(struct ev_task *task)
{
	assert(task);
	struct io_sock_stream_impl *impl = structof(
			task, struct io_sock_stream_impl, recvoob_task);

	int iError = WSAGetLastError();

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	// Process as many receive operations as possible. During the I/O
	// operation, the mutex will be unlocked.
	int wouldblock = 0;
	task = io_sock_stream_impl_do_recv_task(impl, &impl->recvoob_queue,
			&impl->current_recvoob, &wouldblock);
	impl->recvoob_posted = 0;
#ifdef _POSIX_C_SOURCE
	// If the operation would block (and the socket has not been closed in
	// the mean time), start watching the file descriptor.
	if (impl->poll && wouldblock && !sllist_empty(&impl->recvoob_queue)
			&& impl->handle.fd != -1 && !impl->shutdown) {
		int events = io_sock_stream_impl_do_get_events(impl);
		io_poll_watch(impl->poll, impl->handle.fd, events,
				&impl->watch);
	}
#endif
	// Repost this task if any receive operations remain in the queue,
	// unless we're waiting the file descriptor to become ready (which we
	// never do on Windows).
#if _WIN32
	int watch = 0;
#else
	int watch = impl->poll && wouldblock;
#endif
	int post_recvoob = !sllist_empty(&impl->recvoob_queue) && !watch
			&& !impl->shutdown;
	if (post_recvoob)
		impl->recvoob_posted = 1;
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif

	if (task && wouldblock)
		// The operation would block but was canceled before it could be
		// requeued.
		io_sock_stream_recv_post(task, -1, ERROR_OPERATION_ABORTED);

	if (post_recvoob)
		ev_exec_post(impl->recvoob_task.exec, &impl->recvoob_task);

	WSASetLastError(iError);
}

static struct ev_task *
io_sock_stream_impl_do_recv_task(struct io_sock_stream_impl *impl,
		struct sllist *recv_queue, struct ev_task **pcurrent_recv,
		int *pwouldblock)
{
	assert(impl);
	assert(recv_queue);
	assert(pcurrent_recv);

	int wouldblock = 0;

	// Try to process all pending receive operations at once, unless we're
	// in blocking mode.
	struct ev_task *task;
	while ((task = *pcurrent_recv = ev_task_from_node(
				sllist_pop_front(recv_queue)))) {
#if _WIN32
		if (impl->poll)
			// Move the task to the I/O completion port queue.
			sllist_push_back(&impl->recv_iocp_queue, &task->_node);
#endif
		struct io_sock_stream_handle handle = impl->handle;
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
#if _WIN32
		struct io_cp *cp = NULL;
		ssize_t result = io_sock_stream_impl_do_recv(
				impl, &handle, task, &cp);
#else
		ssize_t result = io_sock_stream_impl_do_recv(
				impl, &handle, task);
#endif
		int errc = result >= 0 ? 0 : WSAGetLastError();
#if _WIN32
		if (impl->poll && !errc && handle.skip_iocp)
			// The operation completed synchronously. If possible,
			// skip the I/O completion packet.
			cp->func(cp, result, errc);
#endif
		wouldblock = errc == WSAEAGAIN || errc == WSAEWOULDBLOCK;
		// Check if the operation succeeded or failed immediately.
		int post = !wouldblock;
#if _WIN32
		// Do not post the completion task if we're waiting for an I/O
		// completion packet.
		if (impl->poll && (!errc || errc == ERROR_IO_PENDING))
			post = 0;
#endif
		if (post)
			io_sock_stream_impl_recv_post(impl, task, result, errc);
#if !LELY_NO_THREADS
		mtx_lock(&impl->mtx);
#endif
#if _WIN32
		if (impl->poll && wouldblock)
			sllist_remove(&impl->recv_iocp_queue, &task->_node);
#endif
		if (task == *pcurrent_recv) {
			// Put the receive operation back on the queue if it
			// would block, unless it was canceled.
			if (wouldblock) {
				sllist_push_front(recv_queue, &task->_node);
				task = NULL;
			}
			*pcurrent_recv = NULL;
		}
		assert(!*pcurrent_recv);
		// Return if the operation did or would block.
		if (wouldblock)
			break;
	}

	if (pwouldblock)
		*pwouldblock = wouldblock;

	return task;
}

static ssize_t
io_sock_stream_impl_do_recv(struct io_sock_stream_impl *impl,
		const struct io_sock_stream_handle *handle,
#if _WIN32
		struct ev_task *task, struct io_cp **pcp)
#else
		struct ev_task *task)
#endif
{
	assert(impl);
	assert(handle);
	assert(task);
	int is_recvmsg = (uintptr_t)task->_data != 0;

	const struct io_buf *buf;
	int bufcnt;
	int flags_ = 0;
	int *flags = &flags_;
	if (is_recvmsg) {
		struct io_sock_stream_recvmsg *recvmsg =
				io_sock_stream_recvmsg_from_task(task);
		buf = recvmsg->buf;
		bufcnt = recvmsg->bufcnt;
		flags = &recvmsg->flags;
	} else {
		struct io_stream_readv *readv = io_stream_readv_from_task(task);
		buf = readv->buf;
		bufcnt = readv->bufcnt;
	}
	assert(bufcnt > 0);

#if _WIN32
	if (!impl->poll)
#endif
		return io_sock_fd_recvmsg(handle->fd, buf, bufcnt, flags, NULL,
				NULL, impl->poll ? 0 : LELY_IO_RX_TIMEOUT);

#if _WIN32
	DWORD dwNumberOfBytesRecvd = 0;
	DWORD dwFlags = 0;
	LPWSAOVERLAPPED lpOverlapped = NULL;

	if (is_recvmsg) {
		struct io_sock_stream_recvmsg *recvmsg =
				io_sock_stream_recvmsg_from_task(task);

		if (flags) {
			if (*flags & IO_MSG_OOB)
				dwFlags |= MSG_OOB;
			if (*flags & IO_MSG_PEEK)
				dwFlags |= MSG_PEEK;
		}

		recvmsg->_handle = (HANDLE)handle->fd;
		recvmsg->_cp = (struct io_cp)IO_CP_INIT(
				&io_sock_stream_impl_recvmsg_cp_func);
		if (pcp)
			*pcp = &recvmsg->_cp;
		lpOverlapped = &recvmsg->_cp.overlapped;
	} else {
		struct io_stream_readv *readv = io_stream_readv_from_task(task);

		readv->_handle = (HANDLE)handle->fd;
		readv->_cp = (struct io_cp)IO_CP_INIT(
				&io_sock_stream_impl_readv_cp_func);
		if (pcp)
			*pcp = &readv->_cp;
		lpOverlapped = &readv->_cp.overlapped;
	}
	task->_data = impl;

	// clang-format off
	if (WSARecvFrom(handle->fd, (LPWSABUF)buf, bufcnt,
			 &dwNumberOfBytesRecvd, &dwFlags, NULL, NULL,
			 lpOverlapped, NULL) == SOCKET_ERROR) {
		// clang-format on
		if (WSAGetLastError() != WSA_IO_PENDING)
			task->_data = (void *)(uintptr_t)is_recvmsg;
		return -1;
	}

	if (flags) {
		*flags = 0;
		if (dwFlags & MSG_OOB)
			*flags |= IO_MSG_OOB;
	}

	return dwNumberOfBytesRecvd;
#endif
}

#if _WIN32

static void
io_sock_stream_impl_recvmsg_cp_func(struct io_cp *cp, size_t nbytes, int errc)
{
	assert(cp);
	struct io_sock_stream_recvmsg *recvmsg =
			structof(cp, struct io_sock_stream_recvmsg, _cp);
	struct io_sock_stream_impl *impl = recvmsg->task._data;
	recvmsg->task._data = (void *)(uintptr_t)1;
	assert(impl);

	recvmsg->flags = 0;

	SOCKET s = (SOCKET)recvmsg->_handle;

	DWORD cbTransfer = nbytes;
	DWORD dwFlags = 0;
	int iError = WSAGetLastError();
	// clang-format off
	if (WSAGetOverlappedResult(
			s, &cp->overlapped, &cbTransfer, FALSE, &dwFlags)) {
		// clang-format on
		nbytes = cbTransfer;
		if (dwFlags & MSG_OOB)
			recvmsg->flags |= IO_MSG_OOB;
	} else {
		errc = WSAGetLastError();
		WSASetLastError(iError);
	}

	ssize_t result = nbytes || !errc ? (ssize_t)nbytes : -1;
	io_sock_stream_impl_recv_post(impl, &recvmsg->task, result, errc);
}

static void
io_sock_stream_impl_readv_cp_func(struct io_cp *cp, size_t nbytes, int errc)
{
	assert(cp);
	struct io_stream_readv *readv =
			structof(cp, struct io_stream_readv, _cp);
	struct io_sock_stream_impl *impl = readv->task._data;
	readv->task._data = NULL;
	assert(impl);

	ssize_t result = nbytes || !errc ? (ssize_t)nbytes : -1;
	io_sock_stream_impl_recv_post(impl, &readv->task, result, errc);
}

#endif // _WIN32

static void
io_sock_stream_impl_recv_post(struct io_sock_stream_impl *impl,
		struct ev_task *task, ssize_t result, int errc)
{
	assert(task);

#if _WIN32
	assert(impl);
	// Remove the task from the queue, unless it was canceled.
	if (errc != ERROR_OPERATION_ABORTED) {
#if !LELY_NO_THREADS
		mtx_lock(&impl->mtx);
#endif
		sllist_remove(&impl->recv_iocp_queue, &task->_node);
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
	}
#else
	(void)impl;
#endif

	io_sock_stream_recv_post(task, result, errc);
}

static void
io_sock_stream_impl_send_task_func(struct ev_task *task)
{
	assert(task);
	struct io_sock_stream_impl *impl =
			structof(task, struct io_sock_stream_impl, send_task);

	int iError = WSAGetLastError();

	int wouldblock = 0;

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	// Try to process all pending send operations at once, unless we're in
	// blocking mode.
	while ((task = impl->current_send = ev_task_from_node(
				sllist_pop_front(&impl->send_queue)))) {
#if _WIN32
		if (impl->poll)
			// Move the task to the I/O completion port queue.
			sllist_push_back(&impl->send_iocp_queue, &task->_node);
#endif
		struct io_sock_stream_handle handle = impl->handle;
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
#if _WIN32
		struct io_cp *cp = NULL;
		ssize_t result = io_sock_stream_impl_do_send(
				impl, &handle, task, &cp);
#else
		ssize_t result = io_sock_stream_impl_do_send(
				impl, &handle, task);
#endif
		int errc = result >= 0 ? 0 : WSAGetLastError();
#if _WIN32
		if (impl->poll && !errc && handle.skip_iocp)
			// The operation completed synchronously. If possible,
			// skip the I/O completion packet.
			cp->func(cp, result, errc);
#endif
		wouldblock = errc == WSAEAGAIN || errc == WSAEWOULDBLOCK;
		// Check if the operation succeeded or failed immediately.
		int post = !wouldblock;
#if _WIN32
		// Do not post the completion task if we're waiting for an I/O
		// completion packet.
		if (impl->poll && (!errc || errc == ERROR_IO_PENDING))
			post = 0;
#endif
		if (post)
			io_sock_stream_impl_send_post(impl, task, result, errc);
#if !LELY_NO_THREADS
		mtx_lock(&impl->mtx);
#endif
#if _WIN32
		if (impl->poll && wouldblock)
			sllist_remove(&impl->send_iocp_queue, &task->_node);
#endif
		if (task == impl->current_send) {
			// Put the send operation back on the queue if it would
			// block, unless it was canceled.
			if (wouldblock) {
				sllist_push_front(&impl->send_queue,
						&task->_node);
				task = NULL;
			}
			impl->current_send = NULL;
		}
		assert(!impl->current_send);
		// Stop if the operation did or would block.
		if (!impl->poll || wouldblock)
			break;
	}
	impl->send_posted = 0;
#ifdef _POSIX_C_SOURCE
	// If the operation would block (and the socket has not been closed in
	// the mean time), start watching the file descriptor.
	if (impl->poll && wouldblock && !sllist_empty(&impl->send_queue)
			&& impl->handle.fd != -1 && !impl->shutdown) {
		int events = io_sock_stream_impl_do_get_events(impl);
		io_poll_watch(impl->poll, impl->handle.fd, events,
				&impl->watch);
	}
#endif
	// Repost this task if any send operations remain in the queue, unless
	// we're waiting the file descriptor to become ready (which we never do
	// on Windows).
#if _WIN32
	int watch = 0;
#else
	int watch = impl->poll && wouldblock;
#endif
	int post_send = !sllist_empty(&impl->send_queue) && !watch
			&& !impl->shutdown;
	if (post_send)
		impl->send_posted = 1;
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif

	if (task && wouldblock)
		// The operation would block but was canceled before it could be
		// requeued.
		io_sock_stream_send_post(task, -1, ERROR_OPERATION_ABORTED);

	if (post_send)
		ev_exec_post(impl->send_task.exec, &impl->send_task);

	WSASetLastError(iError);
}

static ssize_t
io_sock_stream_impl_do_send(struct io_sock_stream_impl *impl,
		const struct io_sock_stream_handle *handle,
#if _WIN32
		struct ev_task *task, struct io_cp **pcp)
#else
		struct ev_task *task)
#endif
{
	assert(impl);
	assert(task);
	int is_sendmsg = (uintptr_t)task->_data != 0;

	const struct io_buf *buf;
	int bufcnt;
	int flags = 0;
	if (is_sendmsg) {
		struct io_sock_stream_sendmsg *sendmsg =
				io_sock_stream_sendmsg_from_task(task);
		buf = sendmsg->buf;
		bufcnt = sendmsg->bufcnt;
		flags = sendmsg->flags;
	} else {
		struct io_stream_writev *writev =
				io_stream_writev_from_task(task);
		buf = writev->buf;
		bufcnt = writev->bufcnt;
	}
	assert(bufcnt > 0);

#if _WIN32
	if (!impl->poll)
#endif
		return io_sock_fd_sendmsg(handle->fd, buf, bufcnt, flags, NULL,
				NULL, impl->poll ? 0 : LELY_IO_TX_TIMEOUT);

#if _WIN32
	DWORD dwNumberOfBytesSent = 0;
	DWORD dwFlags = 0;
	LPWSAOVERLAPPED lpOverlapped = NULL;

	if (is_sendmsg) {
		struct io_sock_stream_sendmsg *sendmsg =
				io_sock_stream_sendmsg_from_task(task);

		if (flags & IO_MSG_DONTROUTE)
			dwFlags |= MSG_DONTROUTE;
		if (flags & IO_MSG_OOB)
			dwFlags |= MSG_OOB;

		sendmsg->_handle = (HANDLE)handle->fd;
		sendmsg->_cp = (struct io_cp)IO_CP_INIT(
				&io_sock_stream_impl_sendmsg_cp_func);
		if (pcp)
			*pcp = &sendmsg->_cp;
		lpOverlapped = &sendmsg->_cp.overlapped;
	} else {
		struct io_stream_writev *writev =
				io_stream_writev_from_task(task);

		writev->_handle = (HANDLE)handle->fd;
		writev->_cp = (struct io_cp)IO_CP_INIT(
				&io_sock_stream_impl_writev_cp_func);
		if (pcp)
			*pcp = &writev->_cp;
		lpOverlapped = &writev->_cp.overlapped;
	}
	task->_data = impl;

	// clang-format off
	if (WSASendTo(handle->fd, (LPWSABUF)buf, bufcnt, &dwNumberOfBytesSent,
			dwFlags, NULL, 0, lpOverlapped, NULL) == SOCKET_ERROR) {
		// clang-format on
		if (WSAGetLastError() != WSA_IO_PENDING)
			task->_data = (void *)(uintptr_t)is_sendmsg;
		return -1;
	}

	return dwNumberOfBytesSent;
#endif
}

#if _WIN32

static void
io_sock_stream_impl_sendmsg_cp_func(struct io_cp *cp, size_t nbytes, int errc)
{
	assert(cp);
	struct io_sock_stream_sendmsg *sendmsg =
			structof(cp, struct io_sock_stream_sendmsg, _cp);
	struct io_sock_stream_impl *impl = sendmsg->task._data;
	sendmsg->task._data = (void *)(uintptr_t)1;
	assert(impl);

	ssize_t result = nbytes || !errc ? (ssize_t)nbytes : -1;
	io_sock_stream_impl_send_post(impl, &sendmsg->task, result, errc);
}

static void
io_sock_stream_impl_writev_cp_func(struct io_cp *cp, size_t nbytes, int errc)
{
	assert(cp);
	struct io_stream_writev *writev =
			structof(cp, struct io_stream_writev, _cp);
	struct io_sock_stream_impl *impl = writev->task._data;
	writev->task._data = NULL;
	assert(impl);

	ssize_t result = nbytes || !errc ? (ssize_t)nbytes : -1;
	io_sock_stream_impl_send_post(impl, &writev->task, result, errc);
}

#endif // _WIN32

static void
io_sock_stream_impl_send_post(struct io_sock_stream_impl *impl,
		struct ev_task *task, ssize_t result, int errc)
{
	assert(task);

#if _WIN32
	assert(impl);
	// Remove the task from the queue, unless it was canceled.
	if (errc != ERROR_OPERATION_ABORTED) {
#if !LELY_NO_THREADS
		mtx_lock(&impl->mtx);
#endif
		sllist_remove(&impl->send_iocp_queue, &task->_node);
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
	}
#else
	(void)impl;
#endif

	io_sock_stream_send_post(task, result, errc);
}

static inline struct io_sock_stream_impl *
io_sock_stream_impl_from_dev(const io_dev_t *dev)
{
	assert(dev);

	return structof(dev, struct io_sock_stream_impl, dev_vptr);
}

static inline struct io_sock_stream_impl *
io_sock_stream_impl_from_sock(const io_sock_t *sock)
{
	assert(sock);

	return structof(sock, struct io_sock_stream_impl, sock_vptr);
}

static inline struct io_sock_stream_impl *
io_sock_stream_impl_from_stream(const io_stream_t *stream)
{
	assert(stream);

	return structof(stream, struct io_sock_stream_impl, stream_vptr);
}

static inline struct io_sock_stream_impl *
io_sock_stream_impl_from_sock_stream(const io_sock_stream_t *sock_stream)
{
	assert(sock_stream);

	return structof(sock_stream, struct io_sock_stream_impl,
			sock_stream_vptr);
}

static inline struct io_sock_stream_impl *
io_sock_stream_impl_from_svc(const struct io_svc *svc)
{
	assert(svc);

	return structof(svc, struct io_sock_stream_impl, svc);
}

static void
io_sock_stream_impl_do_pop(struct io_sock_stream_impl *impl,
		struct sllist *wait_queue, struct sllist *connect_queue,
		struct sllist *recv_queue, struct sllist *send_queue,
		struct ev_task *task)
{
	assert(impl);
	assert(wait_queue);
	assert(connect_queue);
	assert(recv_queue);
	assert(send_queue);

	if (!task) {
		sllist_append(wait_queue, &impl->wait_queue);
		sllist_append(connect_queue, &impl->connect_queue);
		sllist_append(recv_queue, &impl->recv_queue);
		sllist_append(recv_queue, &impl->recvoob_queue);
		sllist_append(send_queue, &impl->send_queue);
	} else if (sllist_remove(&impl->wait_queue, &task->_node)) {
		sllist_push_back(wait_queue, &task->_node);
	} else if (sllist_remove(&impl->connect_queue, &task->_node)) {
		sllist_push_back(connect_queue, &task->_node);
	} else if (sllist_remove(&impl->recv_queue, &task->_node)) {
		sllist_push_back(recv_queue, &task->_node);
	} else if (sllist_remove(&impl->recvoob_queue, &task->_node)) {
		sllist_push_back(recv_queue, &task->_node);
	} else if (sllist_remove(&impl->send_queue, &task->_node)) {
		sllist_push_back(send_queue, &task->_node);
	}
}

#if _WIN32
static size_t
io_sock_stream_impl_do_cancel_iocp(
		struct io_sock_stream_impl *impl, struct ev_task *task)
{
	assert(impl);

	size_t n = 0;
	DWORD dwErrCode = GetLastError();

	HANDLE hFile = INVALID_HANDLE_VALUE;
	LPOVERLAPPED lpOverlapped = NULL;

	// Try to cancel matching I/O event wait operations waiting for a
	// completion packet.
	for (struct slnode **pnode = &impl->wait_iocp_queue.first; *pnode;
			pnode = &(*pnode)->next) {
		struct io_sock_wait *wait = io_sock_wait_from_task(
				ev_task_from_node(*pnode));
		if (task && task != &wait->task)
			continue;
		if (!io_poll_cancel_afd(impl->poll, &wait->_cp))
			continue;
		n += n < SIZE_MAX;
		// Remove the task from the queue.
		if (!(*pnode = (*pnode)->next)) {
			impl->wait_iocp_queue.plast = pnode;
			break;
		}
	}

	// Try to cancel matching connect operations waiting for a completion
	// packet.
	for (struct slnode **pnode = &impl->connect_iocp_queue.first; *pnode;
			pnode = &(*pnode)->next) {
		struct io_sock_stream_connect *connect =
				io_sock_stream_connect_from_task(
						ev_task_from_node(*pnode));
		if (task && task != &connect->task)
			continue;
		// CancelIoEx() only works with the base service provider
		// handle.
		SOCKET s = io_wsa_base_handle((SOCKET)connect->_handle);
		if (s == INVALID_SOCKET)
			continue;
		if (!CancelIoEx((HANDLE)s, &connect->_cp.overlapped))
			continue;
		n += n < SIZE_MAX;
		// Remove the task from the queue.
		if (!(*pnode = (*pnode)->next)) {
			impl->connect_iocp_queue.plast = pnode;
			break;
		}
	}

	// Try to cancel matching receive operations waiting for a completion
	// packet.
	for (struct slnode **pnode = &impl->recv_iocp_queue.first; *pnode;
			pnode = &(*pnode)->next) {
		struct ev_task *recv_task = ev_task_from_node(*pnode);
		int is_recvmsg = (uintptr_t)recv_task->_data & 1;
		if (is_recvmsg) {
			struct io_sock_stream_recvmsg *recvmsg =
					io_sock_stream_recvmsg_from_task(
							recv_task);
			if (task && task != &recvmsg->task)
				continue;
			hFile = recvmsg->_handle;
			lpOverlapped = &recvmsg->_cp.overlapped;
		} else {
			struct io_stream_readv *readv =
					io_stream_readv_from_task(recv_task);
			if (task && task != &readv->task)
				continue;
			hFile = readv->_handle;
			lpOverlapped = &readv->_cp.overlapped;
		}
		// CancelIoEx() only works with the base service provider
		// handle.
		SOCKET s = io_wsa_base_handle((SOCKET)hFile);
		if (s == INVALID_SOCKET)
			continue;
		if (!CancelIoEx((HANDLE)s, lpOverlapped))
			continue;
		n += n < SIZE_MAX;
		// Remove the task from the queue.
		if (!(*pnode = (*pnode)->next)) {
			impl->recv_iocp_queue.plast = pnode;
			break;
		}
	}

	// Try to cancel matching send operations waiting for a completion
	// packet.
	for (struct slnode **pnode = &impl->send_iocp_queue.first; *pnode;
			pnode = &(*pnode)->next) {
		struct ev_task *send_task = ev_task_from_node(*pnode);
		int is_sendmsg = (uintptr_t)send_task->_data & 1;
		if (is_sendmsg) {
			struct io_sock_stream_sendmsg *sendmsg =
					io_sock_stream_sendmsg_from_task(
							send_task);
			if (task && task != &sendmsg->task)
				continue;
			hFile = sendmsg->_handle;
			lpOverlapped = &sendmsg->_cp.overlapped;
		} else {
			struct io_stream_writev *writev =
					io_stream_writev_from_task(send_task);
			if (task && task != &writev->task)
				continue;
			hFile = writev->_handle;
			lpOverlapped = &writev->_cp.overlapped;
		}
		// CancelIoEx() only works with the base service provider
		// handle.
		SOCKET s = io_wsa_base_handle((SOCKET)hFile);
		if (s == INVALID_SOCKET)
			continue;
		if (!CancelIoEx((HANDLE)s, lpOverlapped))
			continue;
		n += n < SIZE_MAX;
		// Remove the task from the queue.
		if (!(*pnode = (*pnode)->next)) {
			impl->send_iocp_queue.plast = pnode;
			break;
		}
	}

	SetLastError(dwErrCode);
	return n;
}
#endif // _WIN32

#ifdef _POSIX_C_SOURCE
static int
io_sock_stream_impl_do_get_events(struct io_sock_stream_impl *impl)
{
	assert(impl);

	int events = 0;
	if (!impl->wait_posted) {
		// Include I/O events from pending wait operations.
		sllist_foreach (&impl->wait_queue, node) {
			struct io_sock_wait *wait = io_sock_wait_from_task(
					ev_task_from_node(node));
			events |= wait->events;
		}
	}
	// Include I/O events from pending connect, read and write operations.
	if (impl->current_connect)
		events |= IO_EVENT_OUT;
	if (!impl->recv_posted && !sllist_empty(&impl->recv_queue))
		events |= IO_EVENT_IN;
	if (!impl->recvoob_posted && !sllist_empty(&impl->recvoob_queue))
		events |= IO_EVENT_PRI;
	if (!impl->send_posted && !sllist_empty(&impl->send_queue))
		events |= IO_EVENT_OUT;
	return events;
}
#endif // _POSIX_C_SOURCE

static size_t
io_sock_stream_do_abort_tasks(struct io_sock_stream_impl *impl)
{
	assert(impl);

	size_t n = 0;

	// Try to abort io_sock_stream_impl_connect_task_func().
	// clang-format off
	if (impl->connect_posted && ev_exec_abort(impl->connect_task.exec,
			&impl->connect_task)) {
		// clang-format on
		impl->connect_posted = 0;
		n++;
	}

	// Try to abort io_sock_stream_impl_wait_task_func().
	// clang-format off
	if (impl->wait_posted && ev_exec_abort(impl->wait_task.exec,
			&impl->wait_task)) {
		// clang-format on
		impl->wait_posted = 0;
		n++;
	}

	// Try to abort io_sock_stream_impl_recv_task_func().
	// clang-format off
	if (impl->recv_posted && ev_exec_abort(impl->recv_task.exec,
			&impl->recv_task)) {
		// clang-format on
		impl->recv_posted = 0;
		n++;
	}

	// Try to abort io_sock_stream_impl_recvoob_task_func().
	// clang-format off
	if (impl->recvoob_posted && ev_exec_abort(impl->recvoob_task.exec,
			&impl->recvoob_task)) {
		// clang-format on
		impl->recvoob_posted = 0;
		n++;
	}

	// Try to abort io_sock_stream_impl_send_task_func().
	// clang-format off
	if (impl->send_posted && ev_exec_abort(impl->send_task.exec,
			&impl->send_task)) {
		// clang-format on
		impl->send_posted = 0;
		n++;
	}

	return n;
}

static SOCKET
io_sock_stream_impl_set_handle(struct io_sock_stream_impl *impl,
		const struct io_sock_stream_handle *handle)
{
	assert(impl);
	assert(handle);

#if _WIN32
	LPFN_CONNECTEX lpfnConnectEx = NULL;
	int iError = WSAGetLastError();
	if (handle->fd != INVALID_SOCKET
			&& !(lpfnConnectEx = io_wsa_get_connectex(handle->fd)))
		// Ignore the error here since we cannot handle it. We notify
		// the user on the first asynchronous connect attempt.
		WSASetLastError(iError);

#endif

	struct sllist wait_queue, connect_queue, recv_queue, send_queue;
	sllist_init(&wait_queue);
	sllist_init(&connect_queue);
	sllist_init(&recv_queue);
	sllist_init(&send_queue);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif

#ifdef _POSIX_C_SOURCE
	if (impl->handle.fd != -1 && !impl->shutdown && impl->poll)
		// Stop monitoring I/O events.
		io_poll_watch(impl->poll, impl->handle.fd, 0, &impl->watch);
#endif
	SOCKET fd = impl->handle.fd;
	impl->handle = *handle;
#if _WIN32
	impl->handle.lpfnConnectEx = lpfnConnectEx;
#endif

	// Cancel pending operations.
	sllist_append(&wait_queue, &impl->wait_queue);
	sllist_append(&connect_queue, &impl->connect_queue);
	sllist_append(&recv_queue, &impl->recv_queue);
	sllist_append(&recv_queue, &impl->recvoob_queue);
	sllist_append(&send_queue, &impl->send_queue);

#if _WIN32
	// Cancel operations waiting for a completion packet.
	io_sock_stream_impl_do_cancel_iocp(impl, NULL);
#endif

	// Mark ongoing send, receive and connect operations as canceled, if
	// necessary.
	impl->current_connect = NULL;
	impl->current_recv = NULL;
	impl->current_recvoob = NULL;
	impl->current_send = NULL;

#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif

	io_sock_wait_queue_post(
			&wait_queue, IO_EVENT_ERR, ERROR_OPERATION_ABORTED);
	io_sock_stream_connect_queue_post(
			&connect_queue, ERROR_OPERATION_ABORTED);
	io_sock_stream_recv_queue_post(
			&recv_queue, -1, ERROR_OPERATION_ABORTED);
	io_sock_stream_send_queue_post(
			&send_queue, -1, ERROR_OPERATION_ABORTED);

	return fd;
}

#endif // _WIN32 || (_POSIX_C_SOURCE && !__NEWLIB__)
