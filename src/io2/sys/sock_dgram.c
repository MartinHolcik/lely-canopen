/**@file
 * This file is part of the I/O library; it contains the datagram socket
 * implementation.
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

#include "sock_dgram.h"

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
#include "../sock_dgram.h"
#if _WIN32
#include "../win32/wsa.h"
#endif

static io_ctx_t *io_sock_dgram_impl_dev_get_ctx(const io_dev_t *dev);
static ev_exec_t *io_sock_dgram_impl_dev_get_exec(const io_dev_t *dev);
static size_t io_sock_dgram_impl_dev_cancel(
		io_dev_t *dev, struct ev_task *task);
static size_t io_sock_dgram_impl_dev_abort(io_dev_t *dev, struct ev_task *task);

// clang-format off
static const struct io_dev_vtbl io_sock_dgram_impl_dev_vtbl = {
	&io_sock_dgram_impl_dev_get_ctx,
	&io_sock_dgram_impl_dev_get_exec,
	&io_sock_dgram_impl_dev_cancel,
	&io_sock_dgram_impl_dev_abort
};
// clang-format on

static io_dev_t *io_sock_dgram_impl_sock_get_dev(const io_sock_t *sock);
static int io_sock_dgram_impl_sock_bind(
		io_sock_t *sock, const struct io_endp *endp, int reuseaddr);
static int io_sock_dgram_impl_sock_getsockname(
		const io_sock_t *sock, struct io_endp *endp);
static int io_sock_dgram_impl_sock_is_open(const io_sock_t *sock);
static int io_sock_dgram_impl_sock_close(io_sock_t *sock);
static int io_sock_dgram_impl_sock_wait(
		io_sock_t *sock, int *events, int timeout);
static void io_sock_dgram_impl_sock_submit_wait(
		io_sock_t *sock, struct io_sock_wait *wait);
static int io_sock_dgram_impl_sock_get_error(io_sock_t *sock);
static int io_sock_dgram_impl_sock_get_nread(const io_sock_t *sock);
static int io_sock_dgram_impl_sock_get_dontroute(const io_sock_t *sock);
static int io_sock_dgram_impl_sock_set_dontroute(io_sock_t *sock, int optval);
static int io_sock_dgram_impl_sock_get_rcvbuf(const io_sock_t *sock);
static int io_sock_dgram_impl_sock_set_rcvbuf(io_sock_t *sock, int optval);
static int io_sock_dgram_impl_sock_get_sndbuf(const io_sock_t *sock);
static int io_sock_dgram_impl_sock_set_sndbuf(io_sock_t *sock, int optval);

// clang-format off
static const struct io_sock_vtbl io_sock_dgram_impl_sock_vtbl = {
	&io_sock_dgram_impl_sock_get_dev,
	&io_sock_dgram_impl_sock_bind,
	&io_sock_dgram_impl_sock_getsockname,
	&io_sock_dgram_impl_sock_is_open,
	&io_sock_dgram_impl_sock_close,
	&io_sock_dgram_impl_sock_wait,
	&io_sock_dgram_impl_sock_submit_wait,
	&io_sock_dgram_impl_sock_get_error,
	&io_sock_dgram_impl_sock_get_nread,
	&io_sock_dgram_impl_sock_get_dontroute,
	&io_sock_dgram_impl_sock_set_dontroute,
	&io_sock_dgram_impl_sock_get_rcvbuf,
	&io_sock_dgram_impl_sock_set_rcvbuf,
	&io_sock_dgram_impl_sock_get_sndbuf,
	&io_sock_dgram_impl_sock_set_sndbuf
};
// clang-format on

static io_sock_t *io_sock_dgram_impl_get_sock(const io_sock_dgram_t *sock);
static int io_sock_dgram_impl_connect(
		io_sock_dgram_t *sock, const struct io_endp *endp);
static int io_sock_dgram_impl_getpeername(
		const io_sock_dgram_t *sock, struct io_endp *endp);
static ssize_t io_sock_dgram_impl_recvmsg(io_sock_dgram_t *sock,
		const struct io_buf *buf, int bufcnt, int *flags,
		struct io_endp *endp, int timeout);
static void io_sock_dgram_impl_submit_recvmsg(
		io_sock_dgram_t *sock, struct io_sock_dgram_recvmsg *recvmsg);
static ssize_t io_sock_dgram_impl_sendmsg(io_sock_dgram_t *sock,
		const struct io_buf *buf, int bufcnt, int flags,
		const struct io_endp *endp, int timeout);
static void io_sock_dgram_impl_submit_sendmsg(
		io_sock_dgram_t *sock, struct io_sock_dgram_sendmsg *sendmsg);
static int io_sock_dgram_impl_get_broadcast(const io_sock_dgram_t *sock);
static int io_sock_dgram_impl_set_broadcast(io_sock_dgram_t *sock, int optval);

// clang-format off
static const struct io_sock_dgram_vtbl io_sock_dgram_impl_vtbl = {
	&io_sock_dgram_impl_get_sock,
	&io_sock_dgram_impl_connect,
	&io_sock_dgram_impl_getpeername,
	&io_sock_dgram_impl_recvmsg,
	&io_sock_dgram_impl_submit_recvmsg,
	&io_sock_dgram_impl_sendmsg,
	&io_sock_dgram_impl_submit_sendmsg,
	&io_sock_dgram_impl_get_broadcast,
	&io_sock_dgram_impl_set_broadcast
};
// clang-format on

static void io_sock_dgram_impl_svc_shutdown(struct io_svc *svc);

// clang-format off
static const struct io_svc_vtbl io_sock_dgram_impl_svc_vtbl = {
	NULL,
	&io_sock_dgram_impl_svc_shutdown
};
// clang-format on

#ifdef _POSIX_C_SOURCE
static void io_sock_dgram_impl_watch_func(
		struct io_poll_watch *watch, int events);
#endif

static void io_sock_dgram_impl_wait_task_func(struct ev_task *task);
#if _WIN32
static void io_sock_dgram_impl_wait_cp_func(
		struct io_cp *cp, size_t nbytes, int errc);
#endif

static void io_sock_dgram_impl_recv_task_func(struct ev_task *task);
static void io_sock_dgram_impl_recvoob_task_func(struct ev_task *task);
static struct ev_task *io_sock_dgram_impl_do_recv_task(
		struct io_sock_dgram_impl *impl, struct sllist *recv_queue,
		struct ev_task **pcurrent_recv, int *pwouldblock);
static ssize_t io_sock_dgram_impl_do_recv(struct io_sock_dgram_impl *impl,
		const struct io_sock_dgram_handle *handle,
		struct io_sock_dgram_recvmsg *recvmsg);
#if _WIN32
static void io_sock_dgram_impl_recv_cp_func(
		struct io_cp *cp, size_t nbytes, int errc);
#endif
static void io_sock_dgram_impl_recvmsg_post(
		struct io_sock_dgram_recvmsg *recvmsg, ssize_t result,
		int errc);

static void io_sock_dgram_impl_send_task_func(struct ev_task *task);
static ssize_t io_sock_dgram_impl_do_send(struct io_sock_dgram_impl *impl,
		const struct io_sock_dgram_handle *handle,
		struct io_sock_dgram_sendmsg *sendmsg);
#if _WIN32
static void io_sock_dgram_impl_send_cp_func(
		struct io_cp *cp, size_t nbytes, int errc);
#endif
static void io_sock_dgram_impl_sendmsg_post(
		struct io_sock_dgram_sendmsg *sendmsg, ssize_t result,
		int errc);

static inline struct io_sock_dgram_impl *io_sock_dgram_impl_from_dev(
		const io_dev_t *dev);
static inline struct io_sock_dgram_impl *io_sock_dgram_impl_from_sock(
		const io_sock_t *sock);
static inline struct io_sock_dgram_impl *io_sock_dgram_impl_from_sock_dgram(
		const io_sock_dgram_t *sock_dgram);
static inline struct io_sock_dgram_impl *io_sock_dgram_impl_from_svc(
		const struct io_svc *svc);

static void io_sock_dgram_impl_do_pop(struct io_sock_dgram_impl *impl,
		struct sllist *wait_queue, struct sllist *recv_queue,
		struct sllist *send_queue, struct ev_task *task);
#if _WIN32
static size_t io_sock_dgram_impl_do_cancel_iocp(
		struct io_sock_dgram_impl *impl, struct ev_task *task);
#endif
#ifdef _POSIX_C_SOURCE
static int io_sock_dgram_impl_do_get_events(struct io_sock_dgram_impl *impl);
#endif

static size_t io_sock_dgram_do_abort_tasks(struct io_sock_dgram_impl *impl);

static SOCKET io_sock_dgram_impl_set_handle(struct io_sock_dgram_impl *impl,
		const struct io_sock_dgram_handle *handle);

int
io_sock_dgram_impl_init(struct io_sock_dgram_impl *impl, io_poll_t *poll,
		ev_exec_t *exec, const struct io_endp_vtbl *endp_vptr)
{
	assert(impl);
	assert(exec);
	assert(endp_vptr);
	io_ctx_t *ctx = poll ? io_poll_get_ctx(poll) : NULL;

	impl->dev_vptr = &io_sock_dgram_impl_dev_vtbl;
	impl->sock_vptr = &io_sock_dgram_impl_sock_vtbl;
	impl->sock_dgram_vptr = &io_sock_dgram_impl_vtbl;

	impl->endp_vptr = endp_vptr;

	impl->poll = poll;

	impl->svc = (struct io_svc)IO_SVC_INIT(&io_sock_dgram_impl_svc_vtbl);
	impl->ctx = ctx;

	impl->exec = exec;

#ifdef _POSIX_C_SOURCE
	impl->watch = (struct io_poll_watch)IO_POLL_WATCH_INIT(
			&io_sock_dgram_impl_watch_func);
#endif

	impl->wait_task = (struct ev_task)EV_TASK_INIT(
			impl->exec, &io_sock_dgram_impl_wait_task_func);
	impl->recv_task = (struct ev_task)EV_TASK_INIT(
			impl->exec, &io_sock_dgram_impl_recv_task_func);
	impl->recvoob_task = (struct ev_task)EV_TASK_INIT(
			impl->exec, &io_sock_dgram_impl_recvoob_task_func);
	impl->send_task = (struct ev_task)EV_TASK_INIT(
			impl->exec, &io_sock_dgram_impl_send_task_func);

#if !LELY_NO_THREADS
	if (mtx_init(&impl->mtx, mtx_plain) != thrd_success)
		return -1;
#endif
	impl->handle = (struct io_sock_dgram_handle)IO_SOCK_DGRAM_HANDLE_INIT;

	impl->shutdown = 0;
	impl->wait_posted = 0;
	impl->recv_posted = 0;
	impl->recvoob_posted = 0;
	impl->send_posted = 0;

	sllist_init(&impl->wait_queue);
#if _WIN32
	sllist_init(&impl->wait_iocp_queue);
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
io_sock_dgram_impl_fini(struct io_sock_dgram_impl *impl)
{
	assert(impl);

	if (impl->ctx)
		io_ctx_remove(impl->ctx, &impl->svc);
	// Cancel all pending tasks.
	io_sock_dgram_impl_svc_shutdown(&impl->svc);

	// Abort ongoing socket operations.
	if (impl->handle.fd != INVALID_SOCKET)
#if _WIN32
		shutdown(impl->handle.fd, SD_BOTH);
#else
		shutdown(impl->handle.fd, SHUT_RDWR);
#endif

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
	// If necessary, busy-wait until io_sock_dgram_impl_wait_task_func(),
	// io_sock_dgram_impl_recv_task_func(),
	// io_sock_dgram_impl_recvoob_task_func() and
	// io_sock_dgram_impl_send_task_func() complete.
	while (impl->wait_posted || impl->recv_posted || impl->recvoob_posted
			|| impl->send_posted) {
		if (io_sock_dgram_do_abort_tasks(impl))
			continue;
		mtx_unlock(&impl->mtx);
		thrd_yield();
		mtx_lock(&impl->mtx);
	}
	mtx_unlock(&impl->mtx);
#endif

	// TODO: Find a reliable way to wait for
	// io_sock_dgram_impl_wait_cp_func(), io_sock_dgram_impl_recv_cp_func()
	// and io_sock_dgram_impl_send_cp_func() to complete.

	// Close the socket.
	io_sock_dgram_impl_sock_close(&impl->sock_vptr);

#if !LELY_NO_THREADS
	mtx_destroy(&impl->mtx);
#endif
}

void
io_sock_dgram_impl_get_handle(const struct io_sock_dgram_impl *impl,
		struct io_sock_dgram_handle *phandle)
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
io_sock_dgram_impl_open(
		struct io_sock_dgram_impl *impl, int family, int protocol)
{
	assert(impl);

	int iError = 0;

#if _WIN32
	SOCKET fd = io_wsa_socket(family, SOCK_DGRAM, protocol);
#else
	SOCKET fd = io_fd_socket(family, SOCK_DGRAM, protocol);
#endif
	if (fd == INVALID_SOCKET) {
		iError = WSAGetLastError();
		goto error_socket;
	}

	struct io_sock_dgram_handle handle = IO_SOCK_DGRAM_HANDLE_INIT;
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
	fd = io_sock_dgram_impl_set_handle(impl, &handle);
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
io_sock_dgram_impl_assign(struct io_sock_dgram_impl *impl,
		const struct io_sock_dgram_handle *handle)
{
	assert(impl);
	assert(handle);

	SOCKET fd = handle->fd;
#if _WIN32
	if (io_wsa_set_nonblock(fd) == -1)
		return -1;
	struct io_sock_dgram_handle handle_ = *handle;
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
	fd = io_sock_dgram_impl_set_handle(impl, handle);
	if (fd != INVALID_SOCKET)
		closesocket(fd);

	return 0;
}

SOCKET
io_sock_dgram_impl_release(struct io_sock_dgram_impl *impl)
{
	struct io_sock_dgram_handle handle = IO_SOCK_DGRAM_HANDLE_INIT;
	return io_sock_dgram_impl_set_handle(impl, &handle);
}

static io_ctx_t *
io_sock_dgram_impl_dev_get_ctx(const io_dev_t *dev)
{
	const struct io_sock_dgram_impl *impl =
			io_sock_dgram_impl_from_dev(dev);

	return impl->ctx;
}

static ev_exec_t *
io_sock_dgram_impl_dev_get_exec(const io_dev_t *dev)
{
	const struct io_sock_dgram_impl *impl =
			io_sock_dgram_impl_from_dev(dev);

	return impl->exec;
}

static size_t
io_sock_dgram_impl_dev_cancel(io_dev_t *dev, struct ev_task *task)
{
	struct io_sock_dgram_impl *impl = io_sock_dgram_impl_from_dev(dev);

	size_t n = 0;

	struct sllist wait_queue, recv_queue, send_queue;
	sllist_init(&wait_queue);
	sllist_init(&recv_queue);
	sllist_init(&send_queue);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	io_sock_dgram_impl_do_pop(
			impl, &wait_queue, &recv_queue, &send_queue, task);
#if _WIN32
	// Cancel operations waiting for a completion packet.
	n = io_sock_dgram_impl_do_cancel_iocp(impl, task);
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
	size_t nrecvmsg = io_sock_dgram_recvmsg_queue_post(
			&recv_queue, -1, ERROR_OPERATION_ABORTED);
	n = n < SIZE_MAX - nrecvmsg ? n + nrecvmsg : SIZE_MAX;
	size_t nsendmsg = io_sock_dgram_sendmsg_queue_post(
			&send_queue, -1, ERROR_OPERATION_ABORTED);
	n = n < SIZE_MAX - nsendmsg ? n + nsendmsg : SIZE_MAX;

	return n;
}

static size_t
io_sock_dgram_impl_dev_abort(io_dev_t *dev, struct ev_task *task)
{
	struct io_sock_dgram_impl *impl = io_sock_dgram_impl_from_dev(dev);

	struct sllist queue;
	sllist_init(&queue);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	io_sock_dgram_impl_do_pop(impl, &queue, &queue, &queue, task);
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif

	return ev_task_queue_abort(&queue);
}

static io_dev_t *
io_sock_dgram_impl_sock_get_dev(const io_sock_t *sock)
{
	const struct io_sock_dgram_impl *impl =
			io_sock_dgram_impl_from_sock(sock);

	return &impl->dev_vptr;
}

static int
io_sock_dgram_impl_sock_bind(
		io_sock_t *sock, const struct io_endp *endp, int reuseaddr)
{
	struct io_sock_dgram_impl *impl = io_sock_dgram_impl_from_sock(sock);
	struct io_sock_dgram_handle handle = IO_SOCK_DGRAM_HANDLE_INIT;
	io_sock_dgram_impl_get_handle(impl, &handle);

	return io_sock_fd_bind(handle.fd, handle.family, handle.protocol,
			impl->endp_vptr, endp, reuseaddr);
}

static int
io_sock_dgram_impl_sock_getsockname(const io_sock_t *sock, struct io_endp *endp)
{
	const struct io_sock_dgram_impl *impl =
			io_sock_dgram_impl_from_sock(sock);
	struct io_sock_dgram_handle handle = IO_SOCK_DGRAM_HANDLE_INIT;
	io_sock_dgram_impl_get_handle(impl, &handle);

	return io_sock_fd_getsockname(handle.fd, impl->endp_vptr, endp);
}

static int
io_sock_dgram_impl_sock_is_open(const io_sock_t *sock)
{
	struct io_sock_dgram_handle handle = IO_SOCK_DGRAM_HANDLE_INIT;
	io_sock_dgram_impl_get_handle(
			io_sock_dgram_impl_from_sock(sock), &handle);

	return handle.fd != INVALID_SOCKET;
}

static int
io_sock_dgram_impl_sock_close(io_sock_t *sock)
{
	struct io_sock_dgram_impl *impl = io_sock_dgram_impl_from_sock(sock);

	SOCKET fd = io_sock_dgram_impl_release(impl);
	return fd != INVALID_SOCKET ? (!closesocket(fd) ? 0 : -1) : 0;
}

static int
io_sock_dgram_impl_sock_wait(io_sock_t *sock, int *events, int timeout)
{
	struct io_sock_dgram_impl *impl = io_sock_dgram_impl_from_sock(sock);

	struct io_sock_dgram_handle handle = IO_SOCK_DGRAM_HANDLE_INIT;
	io_sock_dgram_impl_get_handle(impl, &handle);

#if _WIN32
	if (impl->poll)
		return io_poll_afd(impl->poll, (HANDLE)handle.base, events,
				timeout);
#endif
	return io_sock_fd_wait(handle.fd, events, timeout);
}

static void
io_sock_dgram_impl_sock_submit_wait(io_sock_t *sock, struct io_sock_wait *wait)
{
	struct io_sock_dgram_impl *impl = io_sock_dgram_impl_from_sock(sock);
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
io_sock_dgram_impl_sock_get_error(io_sock_t *sock)
{
	struct io_sock_dgram_handle handle = IO_SOCK_DGRAM_HANDLE_INIT;
	io_sock_dgram_impl_get_handle(
			io_sock_dgram_impl_from_sock(sock), &handle);

	return io_sock_fd_get_error(handle.fd);
}

static int
io_sock_dgram_impl_sock_get_nread(const io_sock_t *sock)
{
	struct io_sock_dgram_handle handle = IO_SOCK_DGRAM_HANDLE_INIT;
	io_sock_dgram_impl_get_handle(
			io_sock_dgram_impl_from_sock(sock), &handle);

	return io_sock_fd_get_nread(handle.fd);
}

static int
io_sock_dgram_impl_sock_get_dontroute(const io_sock_t *sock)
{
	struct io_sock_dgram_handle handle = IO_SOCK_DGRAM_HANDLE_INIT;
	io_sock_dgram_impl_get_handle(
			io_sock_dgram_impl_from_sock(sock), &handle);

	return io_sock_fd_get_dontroute(handle.fd);
}

static int
io_sock_dgram_impl_sock_set_dontroute(io_sock_t *sock, int optval)
{
	struct io_sock_dgram_handle handle = IO_SOCK_DGRAM_HANDLE_INIT;
	io_sock_dgram_impl_get_handle(
			io_sock_dgram_impl_from_sock(sock), &handle);

	return io_sock_fd_set_dontroute(handle.fd, optval);
}

static int
io_sock_dgram_impl_sock_get_rcvbuf(const io_sock_t *sock)
{
	struct io_sock_dgram_handle handle = IO_SOCK_DGRAM_HANDLE_INIT;
	io_sock_dgram_impl_get_handle(
			io_sock_dgram_impl_from_sock(sock), &handle);

	return io_sock_fd_get_rcvbuf(handle.fd);
}

static int
io_sock_dgram_impl_sock_set_rcvbuf(io_sock_t *sock, int optval)
{
	struct io_sock_dgram_handle handle = IO_SOCK_DGRAM_HANDLE_INIT;
	io_sock_dgram_impl_get_handle(
			io_sock_dgram_impl_from_sock(sock), &handle);

	return io_sock_fd_set_rcvbuf(handle.fd, optval);
}

static int
io_sock_dgram_impl_sock_get_sndbuf(const io_sock_t *sock)
{
	struct io_sock_dgram_handle handle = IO_SOCK_DGRAM_HANDLE_INIT;
	io_sock_dgram_impl_get_handle(
			io_sock_dgram_impl_from_sock(sock), &handle);

	return io_sock_fd_get_sndbuf(handle.fd);
}

static int
io_sock_dgram_impl_sock_set_sndbuf(io_sock_t *sock, int optval)
{
	struct io_sock_dgram_handle handle = IO_SOCK_DGRAM_HANDLE_INIT;
	io_sock_dgram_impl_get_handle(
			io_sock_dgram_impl_from_sock(sock), &handle);

	return io_sock_fd_set_sndbuf(handle.fd, optval);
}

static io_sock_t *
io_sock_dgram_impl_get_sock(const io_sock_dgram_t *sock)
{
	const struct io_sock_dgram_impl *impl =
			io_sock_dgram_impl_from_sock_dgram(sock);

	return &impl->sock_vptr;
}

static int
io_sock_dgram_impl_connect(io_sock_dgram_t *sock, const struct io_endp *endp)
{
	struct io_sock_dgram_impl *impl =
			io_sock_dgram_impl_from_sock_dgram(sock);
	struct io_sock_dgram_handle handle = IO_SOCK_DGRAM_HANDLE_INIT;
	io_sock_dgram_impl_get_handle(impl, &handle);

	return io_sock_fd_connect(handle.fd, impl->endp_vptr, endp, 1);
}

static int
io_sock_dgram_impl_getpeername(
		const io_sock_dgram_t *sock, struct io_endp *endp)
{
	const struct io_sock_dgram_impl *impl =
			io_sock_dgram_impl_from_sock_dgram(sock);
	struct io_sock_dgram_handle handle = IO_SOCK_DGRAM_HANDLE_INIT;
	io_sock_dgram_impl_get_handle(impl, &handle);

	return io_sock_fd_getpeername(handle.fd, impl->endp_vptr, endp);
}

static ssize_t
io_sock_dgram_impl_recvmsg(io_sock_dgram_t *sock, const struct io_buf *buf,
		int bufcnt, int *flags, struct io_endp *endp, int timeout)
{
	struct io_sock_dgram_impl *impl =
			io_sock_dgram_impl_from_sock_dgram(sock);
	struct io_sock_dgram_handle handle = IO_SOCK_DGRAM_HANDLE_INIT;
	io_sock_dgram_impl_get_handle(impl, &handle);

	return io_sock_fd_recvmsg(handle.fd, buf, bufcnt, flags,
			impl->endp_vptr, endp, timeout);
}

static void
io_sock_dgram_impl_submit_recvmsg(
		io_sock_dgram_t *sock, struct io_sock_dgram_recvmsg *recvmsg)
{
	struct io_sock_dgram_impl *impl =
			io_sock_dgram_impl_from_sock_dgram(sock);
	assert(recvmsg);
	struct ev_task *task = &recvmsg->task;

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
		io_sock_dgram_recvmsg_post(
				recvmsg, -1, ERROR_OPERATION_ABORTED);
	} else if (recvmsg->bufcnt <= 0) {
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		io_sock_dgram_recvmsg_post(recvmsg, -1, WSAEINVAL);
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
io_sock_dgram_impl_sendmsg(io_sock_dgram_t *sock, const struct io_buf *buf,
		int bufcnt, int flags, const struct io_endp *endp, int timeout)
{
	struct io_sock_dgram_impl *impl =
			io_sock_dgram_impl_from_sock_dgram(sock);
	struct io_sock_dgram_handle handle = IO_SOCK_DGRAM_HANDLE_INIT;
	io_sock_dgram_impl_get_handle(impl, &handle);

	return io_sock_fd_sendmsg(handle.fd, buf, bufcnt, flags,
			impl->endp_vptr, endp, timeout);
}

static void
io_sock_dgram_impl_submit_sendmsg(
		io_sock_dgram_t *sock, struct io_sock_dgram_sendmsg *sendmsg)
{
	struct io_sock_dgram_impl *impl =
			io_sock_dgram_impl_from_sock_dgram(sock);
	assert(sendmsg);
	struct ev_task *task = &sendmsg->task;

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
		io_sock_dgram_sendmsg_post(
				sendmsg, -1, ERROR_OPERATION_ABORTED);
	} else if (sendmsg->bufcnt <= 0) {
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		io_sock_dgram_sendmsg_post(sendmsg, -1, WSAEINVAL);
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
io_sock_dgram_impl_get_broadcast(const io_sock_dgram_t *sock)
{
	struct io_sock_dgram_handle handle = IO_SOCK_DGRAM_HANDLE_INIT;
	io_sock_dgram_impl_get_handle(
			io_sock_dgram_impl_from_sock_dgram(sock), &handle);

	int optval = 0;
	// clang-format off
	if (getsockopt(handle.fd, SOL_SOCKET, SO_BROADCAST, (void *)&optval,
			&(socklen_t){ sizeof(optval) }) == SOCKET_ERROR)
		// clang-format on
		return -1;
	return optval;
}

static int
io_sock_dgram_impl_set_broadcast(io_sock_dgram_t *sock, int optval)
{
	struct io_sock_dgram_handle handle = IO_SOCK_DGRAM_HANDLE_INIT;
	io_sock_dgram_impl_get_handle(
			io_sock_dgram_impl_from_sock_dgram(sock), &handle);

	// clang-format off
	return !setsockopt(handle.fd, SOL_SOCKET, SO_BROADCAST, (void *)&optval,
			sizeof(optval)) ? 0 : -1;
	// clang-format on
}

static void
io_sock_dgram_impl_svc_shutdown(struct io_svc *svc)
{
	struct io_sock_dgram_impl *impl = io_sock_dgram_impl_from_svc(svc);
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

		// Try to abort io_sock_dgram_impl_wait_task_func(),
		// io_sock_dgram_impl_recv_task_func(),
		// io_sock_dgram_impl_recvoob_task_func() and
		// io_sock_dgram_impl_send_task_func().
		io_sock_dgram_do_abort_tasks(impl);
	}
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif

	if (shutdown)
		// Cancel all pending operations.
		io_sock_dgram_impl_dev_cancel(dev, NULL);
}

#ifdef _POSIX_C_SOURCE
static void
io_sock_dgram_impl_watch_func(struct io_poll_watch *watch, int events)
{
	assert(watch);
	struct io_sock_dgram_impl *impl =
			structof(watch, struct io_sock_dgram_impl, watch);

	struct sllist wait_queue;
	sllist_init(&wait_queue);
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

	if (recv_task) {
		struct io_sock_dgram_recvmsg *recvmsg =
				io_sock_dgram_recvmsg_from_task(recv_task);
		io_sock_dgram_recvmsg_post(recvmsg, -1, errc);
	}

	if (recvoob_task) {
		struct io_sock_dgram_recvmsg *recvmsg =
				io_sock_dgram_recvmsg_from_task(recvoob_task);
		io_sock_dgram_recvmsg_post(recvmsg, -1, errc);
	}

	if (send_task) {
		struct io_sock_dgram_sendmsg *sendmsg =
				io_sock_dgram_sendmsg_from_task(send_task);
		io_sock_dgram_sendmsg_post(sendmsg, -1, errc);
	}

	if (post_recv)
		ev_exec_post(impl->recv_task.exec, &impl->recv_task);
	if (post_recvoob)
		ev_exec_post(impl->recvoob_task.exec, &impl->recvoob_task);
	if (post_send)
		ev_exec_post(impl->send_task.exec, &impl->send_task);
}
#endif // _POSIX_C_SOURCE

static void
io_sock_dgram_impl_wait_task_func(struct ev_task *task)
{
	assert(task);
	struct io_sock_dgram_impl *impl =
			structof(task, struct io_sock_dgram_impl, wait_task);

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
					&io_sock_dgram_impl_wait_cp_func);
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
		events = io_sock_dgram_impl_do_get_events(impl);
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
io_sock_dgram_impl_wait_cp_func(struct io_cp *cp, size_t nbytes, int errc)
{
	assert(cp);
	struct io_sock_wait *wait = structof(cp, struct io_sock_wait, _cp);
	(void)nbytes;

	// Remove the task from the queue, unless it was canceled.
	if (wait->task._data && errc != ERROR_OPERATION_ABORTED) {
		struct io_sock_dgram_impl *impl = wait->task._data;
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
io_sock_dgram_impl_recv_task_func(struct ev_task *task)
{
	assert(task);
	struct io_sock_dgram_impl *impl =
			structof(task, struct io_sock_dgram_impl, recv_task);

	int iError = WSAGetLastError();

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	// Process as many receive operations as possible. During the I/O
	// operation, the mutex will be unlocked.
	int wouldblock = 0;
	task = io_sock_dgram_impl_do_recv_task(impl, &impl->recv_queue,
			&impl->current_recv, &wouldblock);
	impl->recv_posted = 0;
#ifdef _POSIX_C_SOURCE
	// If the operation would block (and the socket has not been closed in
	// the mean time), start watching the file descriptor.
	if (impl->poll && wouldblock && !sllist_empty(&impl->recv_queue)
			&& impl->handle.fd != -1 && !impl->shutdown) {
		int events = io_sock_dgram_impl_do_get_events(impl);
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
		io_sock_dgram_recvmsg_post(
				io_sock_dgram_recvmsg_from_task(task), -1,
				ERROR_OPERATION_ABORTED);

	if (post_recv)
		ev_exec_post(impl->recv_task.exec, &impl->recv_task);

	WSASetLastError(iError);
}

static void
io_sock_dgram_impl_recvoob_task_func(struct ev_task *task)
{
	assert(task);
	struct io_sock_dgram_impl *impl =
			structof(task, struct io_sock_dgram_impl, recvoob_task);

	int iError = WSAGetLastError();

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	// Process as many receive operations as possible. During the I/O
	// operation, the mutex will be unlocked.
	int wouldblock = 0;
	task = io_sock_dgram_impl_do_recv_task(impl, &impl->recvoob_queue,
			&impl->current_recvoob, &wouldblock);
	impl->recvoob_posted = 0;
#ifdef _POSIX_C_SOURCE
	// If the operation would block (and the socket has not been closed in
	// the mean time), start watching the file descriptor.
	if (impl->poll && wouldblock && !sllist_empty(&impl->recvoob_queue)
			&& impl->handle.fd != -1 && !impl->shutdown) {
		int events = io_sock_dgram_impl_do_get_events(impl);
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
		io_sock_dgram_recvmsg_post(
				io_sock_dgram_recvmsg_from_task(task), -1,
				ERROR_OPERATION_ABORTED);

	if (post_recvoob)
		ev_exec_post(impl->recvoob_task.exec, &impl->recvoob_task);

	WSASetLastError(iError);
}

static struct ev_task *
io_sock_dgram_impl_do_recv_task(struct io_sock_dgram_impl *impl,
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
		struct io_sock_dgram_recvmsg *recvmsg =
				io_sock_dgram_recvmsg_from_task(task);
#if _WIN32
		if ((task->_data = impl->poll ? impl : NULL))
			// Move the task to the I/O completion port queue.
			sllist_push_back(&impl->recv_iocp_queue, &task->_node);
#endif
		struct io_sock_dgram_handle handle = impl->handle;
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		ssize_t result = io_sock_dgram_impl_do_recv(
				impl, &handle, recvmsg);
		int errc = result >= 0 ? 0 : WSAGetLastError();
#if _WIN32
		if (impl->poll && !errc && handle.skip_iocp)
			// The operation completed synchronously. If possible,
			// skip the I/O completion packet.
			io_sock_dgram_impl_recv_cp_func(
					&recvmsg->_cp, result, errc);
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
			io_sock_dgram_impl_recvmsg_post(recvmsg, result, errc);
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
		if (!impl->poll || wouldblock)
			break;
	}

	if (pwouldblock)
		*pwouldblock = wouldblock;

	return task;
}

static ssize_t
io_sock_dgram_impl_do_recv(struct io_sock_dgram_impl *impl,
		const struct io_sock_dgram_handle *handle,
		struct io_sock_dgram_recvmsg *recvmsg)
{
	assert(impl);
	assert(handle);
	assert(recvmsg);
	assert(recvmsg->bufcnt > 0);

#if _WIN32
	if (!impl->poll)
#endif
		return io_sock_fd_recvmsg(handle->fd, recvmsg->buf,
				recvmsg->bufcnt, &recvmsg->flags,
				impl->endp_vptr, recvmsg->endp,
				impl->poll ? 0 : LELY_IO_RX_TIMEOUT);

#if _WIN32
	recvmsg->_handle = (HANDLE)handle->fd;
	recvmsg->_cp = (struct io_cp)IO_CP_INIT(
			&io_sock_dgram_impl_recv_cp_func);

	DWORD dwNumberOfBytesRecvd = 0;

	DWORD dwFlags = 0;
	if (recvmsg->flags & IO_MSG_OOB)
		dwFlags |= MSG_OOB;
	if (recvmsg->flags & IO_MSG_PEEK)
		dwFlags |= MSG_PEEK;

	struct sockaddr *lpFrom = NULL;
	LPINT lpFromlen = NULL;
	if (recvmsg->endp) {
		lpFrom = (struct sockaddr *)&recvmsg->_addr;
		lpFromlen = &recvmsg->_addrlen;
		*(struct sockaddr_storage *)lpFrom = (struct sockaddr_storage){
			.ss_family = AF_UNSPEC
		};
		*lpFromlen = sizeof(struct sockaddr_storage);
	}

	// clang-format off
	if (WSARecvFrom(handle->fd, (LPWSABUF)recvmsg->buf, recvmsg->bufcnt,
			&dwNumberOfBytesRecvd, &dwFlags, lpFrom, lpFromlen,
			&recvmsg->_cp.overlapped, NULL) == SOCKET_ERROR)
		// clang-format on
		return -1;

	recvmsg->flags = 0;
	if (dwFlags & MSG_OOB)
		recvmsg->flags |= IO_MSG_OOB;

	return dwNumberOfBytesRecvd;
#endif
}

#if _WIN32
static void
io_sock_dgram_impl_recv_cp_func(struct io_cp *cp, size_t nbytes, int errc)
{
	assert(cp);
	struct io_sock_dgram_recvmsg *recvmsg =
			structof(cp, struct io_sock_dgram_recvmsg, _cp);
	struct io_sock_dgram_impl *impl = recvmsg->task._data;
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

	// Process the sending address.
	if (result >= 0 && recvmsg->endp) {
		int iError = WSAGetLastError();
		// clang-format off
		if (impl->endp_vptr->load(recvmsg->endp,
				(struct sockaddr *)&recvmsg->_addr,
				recvmsg->_addrlen) == -1) {
			// clang-format on
			if (!errc)
				errc = WSAGetLastError();
			WSASetLastError(iError);
		}
	}

	io_sock_dgram_impl_recvmsg_post(recvmsg, result, errc);
}
#endif // _WIN32

static void
io_sock_dgram_impl_recvmsg_post(
		struct io_sock_dgram_recvmsg *recvmsg, ssize_t result, int errc)
{
	assert(recvmsg);

#if _WIN32
	struct io_sock_dgram_impl *impl = recvmsg->task._data;
	recvmsg->task._data = NULL;
	// Remove the task from the queue, unless it was canceled.
	if (impl && errc != ERROR_OPERATION_ABORTED) {
		assert(impl->poll);
#if !LELY_NO_THREADS
		mtx_lock(&impl->mtx);
#endif
		sllist_remove(&impl->recv_iocp_queue, &recvmsg->task._node);
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
	}
#endif

	io_sock_dgram_recvmsg_post(recvmsg, result, errc);
}

static void
io_sock_dgram_impl_send_task_func(struct ev_task *task)
{
	assert(task);
	struct io_sock_dgram_impl *impl =
			structof(task, struct io_sock_dgram_impl, send_task);

	int iError = WSAGetLastError();

	struct io_sock_dgram_sendmsg *sendmsg = NULL;
	int wouldblock = 0;

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	// Try to process all pending send operations at once, unless we're in
	// blocking mode.
	while ((task = impl->current_send = ev_task_from_node(
				sllist_pop_front(&impl->send_queue)))) {
		sendmsg = io_sock_dgram_sendmsg_from_task(task);
#if _WIN32
		if ((task->_data = impl->poll ? impl : NULL))
			// Move the task to the I/O completion port queue.
			sllist_push_back(&impl->send_iocp_queue, &task->_node);
#endif
		struct io_sock_dgram_handle handle = impl->handle;
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		ssize_t result = io_sock_dgram_impl_do_send(
				impl, &handle, sendmsg);
		int errc = result >= 0 ? 0 : WSAGetLastError();
#if _WIN32
		if (impl->poll && !errc && handle.skip_iocp)
			// The operation completed synchronously. If possible,
			// skip the I/O completion packet.
			io_sock_dgram_impl_send_cp_func(
					&sendmsg->_cp, result, errc);
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
			io_sock_dgram_impl_sendmsg_post(sendmsg, result, errc);
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
		int events = io_sock_dgram_impl_do_get_events(impl);
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
		io_sock_dgram_sendmsg_post(
				io_sock_dgram_sendmsg_from_task(task), -1,
				ERROR_OPERATION_ABORTED);

	if (post_send)
		ev_exec_post(impl->send_task.exec, &impl->send_task);

	WSASetLastError(iError);
}

static ssize_t
io_sock_dgram_impl_do_send(struct io_sock_dgram_impl *impl,
		const struct io_sock_dgram_handle *handle,
		struct io_sock_dgram_sendmsg *sendmsg)
{
	assert(impl);
	assert(handle);
	assert(sendmsg);
	assert(sendmsg->bufcnt > 0);

#if _WIN32
	if (!impl->poll)
#endif
		return io_sock_fd_sendmsg(handle->fd, sendmsg->buf,
				sendmsg->bufcnt, sendmsg->flags,
				impl->endp_vptr, sendmsg->endp,
				impl->poll ? 0 : LELY_IO_TX_TIMEOUT);

#if _WIN32
	sendmsg->_handle = (HANDLE)handle->fd;
	sendmsg->_cp = (struct io_cp)IO_CP_INIT(
			&io_sock_dgram_impl_send_cp_func);

	DWORD dwNumberOfBytesSent = 0;

	DWORD dwFlags = 0;
	if (sendmsg->flags & IO_MSG_DONTROUTE)
		dwFlags |= MSG_DONTROUTE;
	if (sendmsg->flags & IO_MSG_OOB)
		dwFlags |= MSG_OOB;

	const struct sockaddr *lpTo = NULL;
	int iTolen = 0;
	struct sockaddr_storage addr = { .ss_family = AF_UNSPEC };
	if (sendmsg->endp) {
		lpTo = (const struct sockaddr *)&addr;
		iTolen = sizeof(addr);
		// clang-format off
		if (impl->endp_vptr->store(sendmsg->endp,
				(struct sockaddr *)&addr, &iTolen) == -1)
			// clang-format on
			return -1;
	}

	// clang-format off
	if (WSASendTo(handle->fd, (LPWSABUF)sendmsg->buf, sendmsg->bufcnt,
			&dwNumberOfBytesSent, dwFlags, lpTo, iTolen,
			&sendmsg->_cp.overlapped, NULL) == SOCKET_ERROR)
		// clang-format on
		return -1;

	return dwNumberOfBytesSent;
#endif
}

#if _WIN32
static void
io_sock_dgram_impl_send_cp_func(struct io_cp *cp, size_t nbytes, int errc)
{
	assert(cp);
	struct io_sock_dgram_sendmsg *sendmsg =
			structof(cp, struct io_sock_dgram_sendmsg, _cp);

	ssize_t result = nbytes || !errc ? (ssize_t)nbytes : -1;
	io_sock_dgram_impl_sendmsg_post(sendmsg, result, errc);
}
#endif // _WIN32

static void
io_sock_dgram_impl_sendmsg_post(
		struct io_sock_dgram_sendmsg *sendmsg, ssize_t result, int errc)
{
	assert(sendmsg);

#if _WIN32
	struct io_sock_dgram_impl *impl = sendmsg->task._data;
	sendmsg->task._data = NULL;
	// Remove the task from the queue, unless it was canceled.
	if (impl && errc != ERROR_OPERATION_ABORTED) {
		assert(impl->poll);
#if !LELY_NO_THREADS
		mtx_lock(&impl->mtx);
#endif
		sllist_remove(&impl->send_iocp_queue, &sendmsg->task._node);
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
	}
#endif

	io_sock_dgram_sendmsg_post(sendmsg, result, errc);
}

static inline struct io_sock_dgram_impl *
io_sock_dgram_impl_from_dev(const io_dev_t *dev)
{
	assert(dev);

	return structof(dev, struct io_sock_dgram_impl, dev_vptr);
}

static inline struct io_sock_dgram_impl *
io_sock_dgram_impl_from_sock(const io_sock_t *sock)
{
	assert(sock);

	return structof(sock, struct io_sock_dgram_impl, sock_vptr);
}

static inline struct io_sock_dgram_impl *
io_sock_dgram_impl_from_sock_dgram(const io_sock_dgram_t *sock_dgram)
{
	assert(sock_dgram);

	return structof(sock_dgram, struct io_sock_dgram_impl, sock_dgram_vptr);
}

static inline struct io_sock_dgram_impl *
io_sock_dgram_impl_from_svc(const struct io_svc *svc)
{
	assert(svc);

	return structof(svc, struct io_sock_dgram_impl, svc);
}

static void
io_sock_dgram_impl_do_pop(struct io_sock_dgram_impl *impl,
		struct sllist *wait_queue, struct sllist *recv_queue,
		struct sllist *send_queue, struct ev_task *task)
{
	assert(impl);
	assert(wait_queue);
	assert(recv_queue);
	assert(send_queue);

	if (!task) {
		sllist_append(wait_queue, &impl->wait_queue);
		sllist_append(recv_queue, &impl->recv_queue);
		sllist_append(recv_queue, &impl->recvoob_queue);
		sllist_append(send_queue, &impl->send_queue);
	} else if (sllist_remove(&impl->wait_queue, &task->_node)) {
		sllist_push_back(wait_queue, &task->_node);
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
io_sock_dgram_impl_do_cancel_iocp(
		struct io_sock_dgram_impl *impl, struct ev_task *task)
{
	assert(impl);

	size_t n = 0;
	DWORD dwErrCode = GetLastError();

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

	// Try to cancel matching receive operations waiting for a completion
	// packet.
	for (struct slnode **pnode = &impl->recv_iocp_queue.first; *pnode;
			pnode = &(*pnode)->next) {
		struct io_sock_dgram_recvmsg *recvmsg =
				io_sock_dgram_recvmsg_from_task(
						ev_task_from_node(*pnode));
		if (task && task != &recvmsg->task)
			continue;
		// CancelIoEx() only works with the base service provider
		// handle.
		SOCKET s = io_wsa_base_handle((SOCKET)recvmsg->_handle);
		if (s == INVALID_SOCKET)
			continue;
		if (!CancelIoEx((HANDLE)s, &recvmsg->_cp.overlapped))
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
		struct io_sock_dgram_sendmsg *sendmsg =
				io_sock_dgram_sendmsg_from_task(
						ev_task_from_node(*pnode));
		if (task && task != &sendmsg->task)
			continue;
		// CancelIoEx() only works with the base service provider
		// handle.
		SOCKET s = io_wsa_base_handle((SOCKET)sendmsg->_handle);
		if (s == INVALID_SOCKET)
			continue;
		if (!CancelIoEx((HANDLE)s, &sendmsg->_cp.overlapped))
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
io_sock_dgram_impl_do_get_events(struct io_sock_dgram_impl *impl)
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
	// Include I/O events from pending read and write operations.
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
io_sock_dgram_do_abort_tasks(struct io_sock_dgram_impl *impl)
{
	assert(impl);

	size_t n = 0;

	// Try to abort io_sock_dgram_impl_wait_task_func().
	// clang-format off
	if (impl->wait_posted && ev_exec_abort(impl->wait_task.exec,
			&impl->wait_task)) {
		// clang-format on
		impl->wait_posted = 0;
		n++;
	}

	// Try to abort io_sock_dgram_impl_recv_task_func().
	// clang-format off
	if (impl->recv_posted && ev_exec_abort(impl->recv_task.exec,
			&impl->recv_task)) {
		// clang-format on
		impl->recv_posted = 0;
		n++;
	}

	// Try to abort io_sock_dgram_impl_recvoob_task_func().
	// clang-format off
	if (impl->recvoob_posted && ev_exec_abort(impl->recvoob_task.exec,
			&impl->recvoob_task)) {
		// clang-format on
		impl->recvoob_posted = 0;
		n++;
	}

	// Try to abort io_sock_dgram_impl_send_task_func().
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
io_sock_dgram_impl_set_handle(struct io_sock_dgram_impl *impl,
		const struct io_sock_dgram_handle *handle)
{
	assert(impl);
	assert(handle);

	struct sllist wait_queue, recv_queue, send_queue;
	sllist_init(&wait_queue);
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

	// Cancel pending operations.
	sllist_append(&wait_queue, &impl->wait_queue);
	sllist_append(&recv_queue, &impl->recv_queue);
	sllist_append(&recv_queue, &impl->recvoob_queue);
	sllist_append(&send_queue, &impl->send_queue);

#if _WIN32
	// Cancel operations waiting for a completion packet.
	io_sock_dgram_impl_do_cancel_iocp(impl, NULL);
#endif

	// Mark ongoing send and receive operations as canceled, if necessary.
	impl->current_recv = NULL;
	impl->current_recvoob = NULL;
	impl->current_send = NULL;

#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif

	io_sock_wait_queue_post(
			&wait_queue, IO_EVENT_ERR, ERROR_OPERATION_ABORTED);
	io_sock_dgram_recvmsg_queue_post(
			&recv_queue, -1, ERROR_OPERATION_ABORTED);
	io_sock_dgram_sendmsg_queue_post(
			&send_queue, -1, ERROR_OPERATION_ABORTED);

	return fd;
}

#endif // _WIN32 || (_POSIX_C_SOURCE && !__NEWLIB__)
