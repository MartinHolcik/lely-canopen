/**@file
 * This file is part of the I/O library; it contains the stream socket server
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

#include "sock_stream_srv.h"

#if _WIN32 || (defined(_POSIX_C_SOURCE) && !defined(__NEWLIB__))

#include "sock_stream.h"
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
#include "../sock_stream_srv.h"
#if _WIN32
#include "../win32/wsa.h"
#endif

static io_ctx_t *io_sock_stream_srv_impl_dev_get_ctx(const io_dev_t *dev);
static ev_exec_t *io_sock_stream_srv_impl_dev_get_exec(const io_dev_t *dev);
static size_t io_sock_stream_srv_impl_dev_cancel(
		io_dev_t *dev, struct ev_task *task);
static size_t io_sock_stream_srv_impl_dev_abort(
		io_dev_t *dev, struct ev_task *task);

// clang-format off
static const struct io_dev_vtbl io_sock_stream_srv_impl_dev_vtbl = {
	&io_sock_stream_srv_impl_dev_get_ctx,
	&io_sock_stream_srv_impl_dev_get_exec,
	&io_sock_stream_srv_impl_dev_cancel,
	&io_sock_stream_srv_impl_dev_abort
};
// clang-format on

static io_dev_t *io_sock_stream_srv_impl_sock_get_dev(const io_sock_t *sock);
static int io_sock_stream_srv_impl_sock_bind(
		io_sock_t *sock, const struct io_endp *endp, int reuseaddr);
static int io_sock_stream_srv_impl_sock_getsockname(
		const io_sock_t *sock, struct io_endp *endp);
static int io_sock_stream_srv_impl_sock_is_open(const io_sock_t *sock);
static int io_sock_stream_srv_impl_sock_close(io_sock_t *sock);
static int io_sock_stream_srv_impl_sock_wait(
		io_sock_t *sock, int *events, int timeout);
static void io_sock_stream_srv_impl_sock_submit_wait(
		io_sock_t *sock, struct io_sock_wait *wait);
static int io_sock_stream_srv_impl_sock_get_error(io_sock_t *sock);
static int io_sock_stream_srv_impl_sock_get_nread(const io_sock_t *sock);
static int io_sock_stream_srv_impl_sock_get_dontroute(const io_sock_t *sock);
static int io_sock_stream_srv_impl_sock_set_dontroute(
		io_sock_t *sock, int optval);
static int io_sock_stream_srv_impl_sock_get_rcvbuf(const io_sock_t *sock);
static int io_sock_stream_srv_impl_sock_set_rcvbuf(io_sock_t *sock, int optval);
static int io_sock_stream_srv_impl_sock_get_sndbuf(const io_sock_t *sock);
static int io_sock_stream_srv_impl_sock_set_sndbuf(io_sock_t *sock, int optval);

// clang-format off
static const struct io_sock_vtbl io_sock_stream_srv_impl_sock_vtbl = {
	&io_sock_stream_srv_impl_sock_get_dev,
	&io_sock_stream_srv_impl_sock_bind,
	&io_sock_stream_srv_impl_sock_getsockname,
	&io_sock_stream_srv_impl_sock_is_open,
	&io_sock_stream_srv_impl_sock_close,
	&io_sock_stream_srv_impl_sock_wait,
	&io_sock_stream_srv_impl_sock_submit_wait,
	&io_sock_stream_srv_impl_sock_get_error,
	&io_sock_stream_srv_impl_sock_get_nread,
	&io_sock_stream_srv_impl_sock_get_dontroute,
	&io_sock_stream_srv_impl_sock_set_dontroute,
	&io_sock_stream_srv_impl_sock_get_rcvbuf,
	&io_sock_stream_srv_impl_sock_set_rcvbuf,
	&io_sock_stream_srv_impl_sock_get_sndbuf,
	&io_sock_stream_srv_impl_sock_set_sndbuf
};
// clang-format on

static io_sock_t *io_sock_stream_srv_impl_get_sock(
		const io_sock_stream_srv_t *srv);
static int io_sock_stream_srv_impl_get_maxconn(const io_sock_stream_srv_t *srv);
static int io_sock_stream_srv_impl_listen(
		io_sock_stream_srv_t *srv, int backlog);
static int io_sock_stream_srv_impl_is_listening(
		const io_sock_stream_srv_t *srv);
static int io_sock_stream_srv_impl_accept(io_sock_stream_srv_t *srv,
		io_sock_stream_t *sock, struct io_endp *endp, int timeout);
static void io_sock_stream_srv_impl_submit_accept(io_sock_stream_srv_t *srv,
		struct io_sock_stream_srv_accept *accept);

// clang-format off
static const struct io_sock_stream_srv_vtbl io_sock_stream_srv_impl_vtbl = {
	&io_sock_stream_srv_impl_get_sock,
	&io_sock_stream_srv_impl_get_maxconn,
	&io_sock_stream_srv_impl_listen,
	&io_sock_stream_srv_impl_is_listening,
	&io_sock_stream_srv_impl_accept,
	&io_sock_stream_srv_impl_submit_accept
};
// clang-format on

static void io_sock_stream_srv_impl_svc_shutdown(struct io_svc *svc);

// clang-format off
static const struct io_svc_vtbl io_sock_stream_srv_impl_svc_vtbl = {
	NULL,
	&io_sock_stream_srv_impl_svc_shutdown
};
// clang-format on

#ifdef _POSIX_C_SOURCE
static void io_sock_stream_srv_impl_watch_func(
		struct io_poll_watch *watch, int events);
#endif

static void io_sock_stream_srv_impl_wait_task_func(struct ev_task *task);
#if _WIN32
static void io_sock_stream_srv_impl_wait_cp_func(
		struct io_cp *cp, size_t nbytes, int errc);
#endif

static void io_sock_stream_srv_impl_accept_task_func(struct ev_task *task);
static SOCKET io_sock_stream_srv_impl_do_accept(
		struct io_sock_stream_srv_impl *impl,
		const struct io_sock_stream_srv_handle *handle,
		struct io_sock_stream_srv_accept *accept);
#if _WIN32
static void io_sock_stream_srv_impl_accept_cp_func(
		struct io_cp *cp, size_t nbytes, int errc);
#endif
static void io_sock_stream_srv_impl_accept_post(
		struct io_sock_stream_srv_accept *accept,
		const struct io_sock_stream_handle *handle, int errc);

static inline struct io_sock_stream_srv_impl *io_sock_stream_srv_impl_from_dev(
		const io_dev_t *dev);
static inline struct io_sock_stream_srv_impl *io_sock_stream_srv_impl_from_sock(
		const io_sock_t *sock);
static inline struct io_sock_stream_srv_impl *
io_sock_stream_srv_impl_from_sock_stream_srv(
		const io_sock_stream_srv_t *sock_stream_srv);
static inline struct io_sock_stream_srv_impl *io_sock_stream_srv_impl_from_svc(
		const struct io_svc *svc);

static void io_sock_stream_srv_impl_do_pop(struct io_sock_stream_srv_impl *impl,
		struct sllist *wait_queue, struct sllist *accept_queue,
		struct ev_task *task);
#if _WIN32
static size_t io_sock_stream_srv_impl_do_cancel_iocp(
		struct io_sock_stream_srv_impl *impl, struct ev_task *task);
#endif

static size_t io_sock_stream_srv_do_abort_tasks(
		struct io_sock_stream_srv_impl *impl);

static SOCKET io_sock_stream_srv_impl_set_handle(
		struct io_sock_stream_srv_impl *impl,
		const struct io_sock_stream_srv_handle *handle);

int
io_sock_stream_srv_impl_init(struct io_sock_stream_srv_impl *impl,
		io_poll_t *poll, ev_exec_t *exec,
		const struct io_endp_vtbl *endp_vptr)
{
	assert(impl);
	assert(exec);
	assert(endp_vptr);
	io_ctx_t *ctx = poll ? io_poll_get_ctx(poll) : NULL;

	impl->dev_vptr = &io_sock_stream_srv_impl_dev_vtbl;
	impl->sock_vptr = &io_sock_stream_srv_impl_sock_vtbl;
	impl->sock_stream_srv_vptr = &io_sock_stream_srv_impl_vtbl;

	impl->endp_vptr = endp_vptr;

	impl->poll = poll;

	impl->svc = (struct io_svc)IO_SVC_INIT(
			&io_sock_stream_srv_impl_svc_vtbl);
	impl->ctx = ctx;

	impl->exec = exec;

#ifdef _POSIX_C_SOURCE
	impl->watch = (struct io_poll_watch)IO_POLL_WATCH_INIT(
			&io_sock_stream_srv_impl_watch_func);
#endif

	impl->wait_task = (struct ev_task)EV_TASK_INIT(
			impl->exec, &io_sock_stream_srv_impl_wait_task_func);
	impl->accept_task = (struct ev_task)EV_TASK_INIT(
			impl->exec, &io_sock_stream_srv_impl_accept_task_func);

#if !LELY_NO_THREADS
	if (mtx_init(&impl->mtx, mtx_plain) != thrd_success)
		return -1;
#endif

	impl->handle = (struct io_sock_stream_srv_handle)
			IO_SOCK_STREAM_SRV_HANDLE_INIT;

	impl->shutdown = 0;
	impl->wait_posted = 0;
	impl->accept_posted = 0;

	sllist_init(&impl->wait_queue);
#if _WIN32
	sllist_init(&impl->wait_iocp_queue);
#endif

	sllist_init(&impl->accept_queue);
	impl->current_accept = NULL;
#if _WIN32
	sllist_init(&impl->accept_iocp_queue);
#endif

	if (impl->ctx)
		io_ctx_insert(impl->ctx, &impl->svc);

	return 0;
}

void
io_sock_stream_srv_impl_fini(struct io_sock_stream_srv_impl *impl)
{
	assert(impl);

	if (impl->ctx)
		io_ctx_remove(impl->ctx, &impl->svc);
	// Cancel all pending tasks.
	io_sock_stream_srv_impl_svc_shutdown(&impl->svc);

	// Abort ongoing socket operations.
	if (impl->handle.fd != INVALID_SOCKET)
#if _WIN32
		shutdown(impl->handle.fd, SD_BOTH);
#else
		shutdown(impl->handle.fd, SHUT_RDWR);
#endif

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
	// If necessary, busy-wait until
	// io_sock_stream_srv_impl_wait_task_func() and
	// io_sock_stream_srv_impl_accept_task_func() complete.
	while (impl->wait_posted || impl->accept_posted) {
		if (io_sock_stream_srv_do_abort_tasks(impl))
			continue;
		mtx_unlock(&impl->mtx);
		thrd_yield();
		mtx_lock(&impl->mtx);
	}
	mtx_unlock(&impl->mtx);
#endif

	// TODO: Find a reliable way to wait for
	// io_sock_stream_srv_impl_wait_cp_func() and
	// io_sock_stream_srv_impl_accept_cp_func() to complete.

	// Close the socket.
	io_sock_stream_srv_impl_sock_close(&impl->sock_vptr);

#if !LELY_NO_THREADS
	mtx_destroy(&impl->mtx);
#endif
}

void
io_sock_stream_srv_impl_get_handle(const struct io_sock_stream_srv_impl *impl,
		struct io_sock_stream_srv_handle *phandle)
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
io_sock_stream_srv_impl_open(
		struct io_sock_stream_srv_impl *impl, int family, int protocol)
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

	struct io_sock_stream_srv_handle handle =
			IO_SOCK_STREAM_SRV_HANDLE_INIT;
	handle.fd = fd;
	handle.family = family;
	handle.protocol = protocol;
#if _WIN32
	handle.base = handle.fd;
	// clang-format off
	if (io_sock_fd_init(handle.fd, &handle.base, &handle.family,
			&handle.protocol, &handle.skip_iocp) == -1) {
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
	fd = io_sock_stream_srv_impl_set_handle(impl, &handle);
	if (fd != INVALID_SOCKET)
		closesocket(fd);

	return handle.fd;

#if _WIN32
error_init:
#endif
	closesocket(fd);
error_socket:
	WSASetLastError(iError);
	return INVALID_SOCKET;
}

int
io_sock_stream_srv_impl_assign(struct io_sock_stream_srv_impl *impl,
		const struct io_sock_stream_srv_handle *handle)
{
	assert(impl);
	assert(handle);

	// Check if the socket is already connected.
	int iError = WSAGetLastError();
	WSASetLastError(0);
	struct sockaddr_storage addr = { .ss_family = AF_UNSPEC };
	socklen_t addrlen = sizeof(addr);
	if (!getpeername(handle->fd, (struct sockaddr *)&addr, &addrlen)
			|| WSAGetLastError() != WSAENOTCONN) {
		if (!WSAGetLastError())
			WSASetLastError(WSAEISCONN);
		return -1;
	}
	WSASetLastError(iError);

	SOCKET fd = handle->fd;
#if _WIN32
	if (io_wsa_set_nonblock(fd) == -1)
		return -1;
	struct io_sock_stream_srv_handle handle_ = *handle;
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
	fd = io_sock_stream_srv_impl_set_handle(impl, handle);
	if (fd != INVALID_SOCKET)
		closesocket(fd);

	return 0;
}

SOCKET
io_sock_stream_srv_impl_release(struct io_sock_stream_srv_impl *impl)
{
	struct io_sock_stream_srv_handle handle =
			IO_SOCK_STREAM_SRV_HANDLE_INIT;
	return io_sock_stream_srv_impl_set_handle(impl, &handle);
}

static io_ctx_t *
io_sock_stream_srv_impl_dev_get_ctx(const io_dev_t *dev)
{
	const struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_dev(dev);

	return impl->ctx;
}

static ev_exec_t *
io_sock_stream_srv_impl_dev_get_exec(const io_dev_t *dev)
{
	const struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_dev(dev);

	return impl->exec;
}

static size_t
io_sock_stream_srv_impl_dev_cancel(io_dev_t *dev, struct ev_task *task)
{
	struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_dev(dev);

	size_t n = 0;

	struct sllist wait_queue, accept_queue;
	sllist_init(&wait_queue);
	sllist_init(&accept_queue);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	io_sock_stream_srv_impl_do_pop(impl, &wait_queue, &accept_queue, task);
#if _WIN32
	// Cancel operations waiting for a completion packet.
	n = io_sock_stream_srv_impl_do_cancel_iocp(impl, task);
#endif
	// Mark the ongoing accept operation as canceled, if necessary.
	if (impl->current_accept && (!task || task == impl->current_accept)) {
		impl->current_accept = NULL;
		n += n < SIZE_MAX;
	}
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif

	size_t nwait = io_sock_wait_queue_post(
			&wait_queue, IO_EVENT_ERR, ERROR_OPERATION_ABORTED);
	n = n < SIZE_MAX - nwait ? n + nwait : SIZE_MAX;
	size_t naccept = io_sock_stream_srv_accept_queue_post(
			&accept_queue, ERROR_OPERATION_ABORTED);
	n = n < SIZE_MAX - naccept ? n + naccept : SIZE_MAX;

	return n;
}

static size_t
io_sock_stream_srv_impl_dev_abort(io_dev_t *dev, struct ev_task *task)
{
	struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_dev(dev);

	struct sllist queue;
	sllist_init(&queue);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	io_sock_stream_srv_impl_do_pop(impl, &queue, &queue, task);
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif

	return ev_task_queue_abort(&queue);
}

static io_dev_t *
io_sock_stream_srv_impl_sock_get_dev(const io_sock_t *sock)
{
	const struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_sock(sock);

	return &impl->dev_vptr;
}

static int
io_sock_stream_srv_impl_sock_bind(
		io_sock_t *sock, const struct io_endp *endp, int reuseaddr)
{
	struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_sock(sock);
	struct io_sock_stream_srv_handle handle =
			IO_SOCK_STREAM_SRV_HANDLE_INIT;
	io_sock_stream_srv_impl_get_handle(impl, &handle);

	return io_sock_fd_bind(handle.fd, handle.family, handle.protocol,
			impl->endp_vptr, endp, reuseaddr);
}

static int
io_sock_stream_srv_impl_sock_getsockname(
		const io_sock_t *sock, struct io_endp *endp)
{
	const struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_sock(sock);
	struct io_sock_stream_srv_handle handle =
			IO_SOCK_STREAM_SRV_HANDLE_INIT;
	io_sock_stream_srv_impl_get_handle(impl, &handle);

	return io_sock_fd_getsockname(handle.fd, impl->endp_vptr, endp);
}

static int
io_sock_stream_srv_impl_sock_is_open(const io_sock_t *sock)
{
	const struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_sock(sock);
	struct io_sock_stream_srv_handle handle =
			IO_SOCK_STREAM_SRV_HANDLE_INIT;
	io_sock_stream_srv_impl_get_handle(impl, &handle);

	return handle.fd != INVALID_SOCKET;
}

static int
io_sock_stream_srv_impl_sock_close(io_sock_t *sock)
{
	struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_sock(sock);

	SOCKET fd = io_sock_stream_srv_impl_release(impl);
	return fd != INVALID_SOCKET ? (!closesocket(fd) ? 0 : -1) : 0;
}

static int
io_sock_stream_srv_impl_sock_wait(io_sock_t *sock, int *events, int timeout)
{
	struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_sock(sock);

	struct io_sock_stream_srv_handle handle =
			IO_SOCK_STREAM_SRV_HANDLE_INIT;
	io_sock_stream_srv_impl_get_handle(impl, &handle);

#if _WIN32
	if (impl->poll)
		return io_poll_afd(impl->poll, (HANDLE)handle.base, events,
				timeout);
#endif
	return io_sock_fd_wait(handle.fd, events, timeout);
}

static void
io_sock_stream_srv_impl_sock_submit_wait(
		io_sock_t *sock, struct io_sock_wait *wait)
{
	struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_sock(sock);
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
io_sock_stream_srv_impl_sock_get_error(io_sock_t *sock)
{
	struct io_sock_stream_srv_handle handle =
			IO_SOCK_STREAM_SRV_HANDLE_INIT;
	io_sock_stream_srv_impl_get_handle(
			io_sock_stream_srv_impl_from_sock(sock), &handle);

	return io_sock_fd_get_error(handle.fd);
}

static int
io_sock_stream_srv_impl_sock_get_nread(const io_sock_t *sock)
{
	struct io_sock_stream_srv_handle handle =
			IO_SOCK_STREAM_SRV_HANDLE_INIT;
	io_sock_stream_srv_impl_get_handle(
			io_sock_stream_srv_impl_from_sock(sock), &handle);

	return io_sock_fd_get_nread(handle.fd);
}

static int
io_sock_stream_srv_impl_sock_get_dontroute(const io_sock_t *sock)
{
	struct io_sock_stream_srv_handle handle =
			IO_SOCK_STREAM_SRV_HANDLE_INIT;
	io_sock_stream_srv_impl_get_handle(
			io_sock_stream_srv_impl_from_sock(sock), &handle);

	return io_sock_fd_get_dontroute(handle.fd);
}

static int
io_sock_stream_srv_impl_sock_set_dontroute(io_sock_t *sock, int optval)
{
	struct io_sock_stream_srv_handle handle =
			IO_SOCK_STREAM_SRV_HANDLE_INIT;
	io_sock_stream_srv_impl_get_handle(
			io_sock_stream_srv_impl_from_sock(sock), &handle);

	return io_sock_fd_set_dontroute(handle.fd, optval);
}

static int
io_sock_stream_srv_impl_sock_get_rcvbuf(const io_sock_t *sock)
{
	struct io_sock_stream_srv_handle handle =
			IO_SOCK_STREAM_SRV_HANDLE_INIT;
	io_sock_stream_srv_impl_get_handle(
			io_sock_stream_srv_impl_from_sock(sock), &handle);

	return io_sock_fd_get_rcvbuf(handle.fd);
}

static int
io_sock_stream_srv_impl_sock_set_rcvbuf(io_sock_t *sock, int optval)
{
	struct io_sock_stream_srv_handle handle =
			IO_SOCK_STREAM_SRV_HANDLE_INIT;
	io_sock_stream_srv_impl_get_handle(
			io_sock_stream_srv_impl_from_sock(sock), &handle);

	return io_sock_fd_set_rcvbuf(handle.fd, optval);
}

static int
io_sock_stream_srv_impl_sock_get_sndbuf(const io_sock_t *sock)
{
	struct io_sock_stream_srv_handle handle =
			IO_SOCK_STREAM_SRV_HANDLE_INIT;
	io_sock_stream_srv_impl_get_handle(
			io_sock_stream_srv_impl_from_sock(sock), &handle);

	return io_sock_fd_get_sndbuf(handle.fd);
}

static int
io_sock_stream_srv_impl_sock_set_sndbuf(io_sock_t *sock, int optval)
{
	struct io_sock_stream_srv_handle handle =
			IO_SOCK_STREAM_SRV_HANDLE_INIT;
	io_sock_stream_srv_impl_get_handle(
			io_sock_stream_srv_impl_from_sock(sock), &handle);

	return io_sock_fd_set_sndbuf(handle.fd, optval);
}

static io_sock_t *
io_sock_stream_srv_impl_get_sock(const io_sock_stream_srv_t *srv)
{
	const struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_sock_stream_srv(srv);

	return &impl->sock_vptr;
}

static int
io_sock_stream_srv_impl_get_maxconn(const io_sock_stream_srv_t *srv)
{
	(void)srv;

	return SOMAXCONN;
}

static int
io_sock_stream_srv_impl_listen(io_sock_stream_srv_t *srv, int backlog)
{
	struct io_sock_stream_srv_handle handle =
			IO_SOCK_STREAM_SRV_HANDLE_INIT;
	io_sock_stream_srv_impl_get_handle(
			io_sock_stream_srv_impl_from_sock_stream_srv(srv),
			&handle);

	return !listen(handle.fd, backlog) ? 0 : -1;
}

static int
io_sock_stream_srv_impl_is_listening(const io_sock_stream_srv_t *srv)
{
	struct io_sock_stream_srv_handle handle =
			IO_SOCK_STREAM_SRV_HANDLE_INIT;
	io_sock_stream_srv_impl_get_handle(
			io_sock_stream_srv_impl_from_sock_stream_srv(srv),
			&handle);

	int optval = 0;
	socklen_t optlen = sizeof(optval);
	// clang-format off
	if (getsockopt(handle.fd, SOL_SOCKET, SO_ACCEPTCONN, (void *)&optval,
			&optlen) == SOCKET_ERROR)
		// clang-format on
		return -1;
	return optval != 0;
}

static int
io_sock_stream_srv_impl_accept(io_sock_stream_srv_t *srv,
		io_sock_stream_t *sock, struct io_endp *endp, int timeout)
{
	struct io_sock_stream_srv_impl *srv_impl =
			io_sock_stream_srv_impl_from_sock_stream_srv(srv);
	assert(sock);
	struct io_sock_stream_impl *impl = structof(
			sock, struct io_sock_stream_impl, sock_stream_vptr);
	struct io_sock_stream_srv_handle srv_handle =
			IO_SOCK_STREAM_SRV_HANDLE_INIT;
	io_sock_stream_srv_impl_get_handle(srv_impl, &srv_handle);

	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	handle.fd = io_sock_fd_accept(
			srv_handle.fd, srv_impl->endp_vptr, endp, timeout);
	if (handle.fd == INVALID_SOCKET)
		return -1;
	handle.family = srv_handle.family;
	handle.protocol = srv_handle.protocol;

	if (io_sock_stream_impl_assign(impl, &handle) == -1) {
		int iError = WSAGetLastError();
		closesocket(handle.fd);
		WSASetLastError(iError);
		return -1;
	}

	return 0;
}

static void
io_sock_stream_srv_impl_submit_accept(io_sock_stream_srv_t *srv,
		struct io_sock_stream_srv_accept *accept)
{
	struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_sock_stream_srv(srv);
	assert(accept);
	struct ev_task *task = &accept->task;

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
		io_sock_stream_srv_accept_post(accept, ERROR_OPERATION_ABORTED);
	} else {
		int post_accept = !impl->accept_posted
				&& sllist_empty(&impl->accept_queue);
		sllist_push_back(&impl->accept_queue, &task->_node);
		if (post_accept)
			impl->accept_posted = 1;
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		if (post_accept)
			ev_exec_post(impl->accept_task.exec,
					&impl->accept_task);
	}
}

static void
io_sock_stream_srv_impl_svc_shutdown(struct io_svc *svc)
{
	struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_svc(svc);
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

		// Try to abort io_sock_stream_srv_impl_wait_task_func() and
		// io_sock_stream_srv_impl_accept_task_func().
		io_sock_stream_srv_do_abort_tasks(impl);
	}
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif

	if (shutdown)
		// Cancel all pending operations.
		io_sock_stream_srv_impl_dev_cancel(dev, NULL);
}

#ifdef _POSIX_C_SOURCE
static void
io_sock_stream_srv_impl_watch_func(struct io_poll_watch *watch, int events)
{
	assert(watch);
	struct io_sock_stream_srv_impl *impl =
			structof(watch, struct io_sock_stream_srv_impl, watch);

	struct sllist wait_queue;
	sllist_init(&wait_queue);
	struct ev_task *accept_task = NULL;

	int errc = 0;
	if (events & IO_EVENT_ERR)
		errc = io_sock_get_error(&impl->sock_vptr);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	// Report a socket error to all pending wait operations and the first
	// pending accept operation.
	io_sock_wait_queue_select(&wait_queue, &impl->wait_queue, events, errc);
	if (errc)
		accept_task = ev_task_from_node(
				sllist_pop_front(&impl->accept_queue));

	// Retry any pending accept operations.
	int post_accept = 0;
	int mask = IO_EVENT_IN | IO_EVENT_ERR | IO_EVENT_HUP;
	if ((events & mask) && !sllist_empty(&impl->accept_queue)
			&& !impl->shutdown) {
		post_accept = !impl->accept_posted;
		impl->accept_posted = 1;
	}
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif

	io_sock_wait_queue_post(&wait_queue, events, errc);

	if (accept_task) {
		struct io_sock_stream_srv_accept *accept =
				io_sock_stream_srv_accept_from_task(
						accept_task);
		io_sock_stream_srv_accept_post(accept, errc);
	}

	if (post_accept)
		ev_exec_post(impl->accept_task.exec, &impl->accept_task);
}
#endif // _POSIX_C_SOURCE

static void
io_sock_stream_srv_impl_wait_task_func(struct ev_task *task)
{
	assert(task);
	struct io_sock_stream_srv_impl *impl = structof(
			task, struct io_sock_stream_srv_impl, wait_task);

	int iError = WSAGetLastError();

	struct sllist wait_queue;
	sllist_init(&wait_queue);
	int events = 0;
	int errc = 0;

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
#if _WIN32
	if (!impl->poll)
#endif
		// Obtain the union of all monitored I/O events.
		sllist_foreach (&impl->wait_queue, node) {
			struct io_sock_wait *wait = io_sock_wait_from_task(
					ev_task_from_node(node));
			events |= wait->events;
		}

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
					&io_sock_stream_srv_impl_wait_cp_func);
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
		post_wait = !sllist_empty(&impl->wait_queue) && !impl->shutdown;
#else
		// If there are any pending accept operations, we also need to
		// monitor incoming connections (reported by IO_EVENT_IN).
		if (!sllist_empty(&impl->accept_queue))
			events |= IO_EVENT_IN;
		// Start watching the file descriptor for the monitored events.
		if (events && impl->handle.fd != -1 && !impl->shutdown)
			io_poll_watch(impl->poll, impl->handle.fd, events,
					&impl->watch);
#endif
	} else {
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
		post_wait = !sllist_empty(&impl->wait_queue) && !impl->shutdown;
	}
	impl->wait_posted = post_wait;
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
io_sock_stream_srv_impl_wait_cp_func(struct io_cp *cp, size_t nbytes, int errc)
{
	assert(cp);
	struct io_sock_wait *wait = structof(cp, struct io_sock_wait, _cp);
	(void)nbytes;

	// Remove the task from the queue, unless it was canceled.
	if (wait->task._data && errc != ERROR_OPERATION_ABORTED) {
		struct io_sock_stream_srv_impl *impl = wait->task._data;
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
io_sock_stream_srv_impl_accept_task_func(struct ev_task *task)
{
	assert(task);
	struct io_sock_stream_srv_impl *impl = structof(
			task, struct io_sock_stream_srv_impl, accept_task);

	int iError = WSAGetLastError();

	struct io_sock_stream_srv_accept *accept = NULL;
	int wouldblock = 0;

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	// Try to process all pending accept operations at once, unless we're in
	// blocking mode.
	while ((task = impl->current_accept = ev_task_from_node(
				sllist_pop_front(&impl->accept_queue)))) {
		accept = io_sock_stream_srv_accept_from_task(task);
#if _WIN32
		if ((task->_data = impl->poll ? impl : NULL))
			// Move the task to the I/O completion port queue.
			sllist_push_back(
					&impl->accept_iocp_queue, &task->_node);
#endif
		struct io_sock_stream_srv_handle srv_handle = impl->handle;
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		// Try a blocking, non-blocking or overlapped accept operation
		// without holding the mutex.
		SOCKET fd = io_sock_stream_srv_impl_do_accept(
				impl, &srv_handle, accept);
		int errc = fd != INVALID_SOCKET ? 0 : WSAGetLastError();
#if _WIN32
		if (impl->poll && !errc && srv_handle.skip_iocp)
			// The operation completed synchronously. If possible,
			// skip the I/O completion packet.
			io_sock_stream_srv_impl_accept_cp_func(
					&accept->_cp, 0, errc);
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
		if (post) {
			struct io_sock_stream_handle handle =
					IO_SOCK_STREAM_HANDLE_INIT;
			handle.fd = fd;
			handle.family = srv_handle.family;
			handle.protocol = srv_handle.protocol;
			io_sock_stream_srv_impl_accept_post(
					accept, &handle, errc);
		}
#if !LELY_NO_THREADS
		mtx_lock(&impl->mtx);
#endif
#if _WIN32
		if (impl->poll && wouldblock)
			sllist_remove(&impl->accept_iocp_queue, &task->_node);
#endif
		if (task == impl->current_accept) {
			// Put the accept operation back on the queue if it
			// would block, unless it was canceled.
			if (wouldblock) {
				sllist_push_front(&impl->accept_queue,
						&task->_node);
				task = NULL;
			}
			impl->current_accept = NULL;
		}
		assert(!impl->current_accept);
		// Stop if the operation did or would block.
		if (!impl->poll || wouldblock)
			break;
	}
#ifdef _POSIX_C_SOURCE
	// If the operation would block (and the socket has not been closed in
	// the mean time), start watching the file descriptor.
	if (impl->poll && wouldblock && !sllist_empty(&impl->accept_queue)
			&& impl->handle.fd != -1 && !impl->shutdown) {
		int events = IO_EVENT_IN;
		// Include I/O events from pending wait operations.
		sllist_foreach (&impl->wait_queue, node) {
			struct io_sock_wait *wait = io_sock_wait_from_task(
					ev_task_from_node(node));
			events |= wait->events;
		}
		io_poll_watch(impl->poll, impl->handle.fd, events,
				&impl->watch);
	}
#endif
	// Repost this task if any accept operations remain in the
	// queue, unless we're waiting the file descriptor to become
	// ready (which we never do on Windows).
#if _WIN32
	int watch = 0;
#else
	int watch = impl->poll && wouldblock;
#endif
	int post_accept = impl->accept_posted =
			!sllist_empty(&impl->accept_queue) && !watch
			&& !impl->shutdown;
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif

	if (task && wouldblock) {
		accept = io_sock_stream_srv_accept_from_task(task);
		// The operation would block but was canceled before it could be
		// requeued.
		struct io_sock_stream_handle handle =
				IO_SOCK_STREAM_HANDLE_INIT;
		io_sock_stream_srv_impl_accept_post(
				accept, &handle, ERROR_OPERATION_ABORTED);
	}

	if (post_accept)
		ev_exec_post(impl->accept_task.exec, &impl->accept_task);

	WSASetLastError(iError);
}

static SOCKET
io_sock_stream_srv_impl_do_accept(struct io_sock_stream_srv_impl *impl,
		const struct io_sock_stream_srv_handle *handle,
		struct io_sock_stream_srv_accept *accept)
{
	assert(impl);
	assert(handle);
	assert(accept);

#if _WIN32
	if (!impl->poll)
#endif
		return io_sock_fd_accept(handle->fd, impl->endp_vptr,
				accept->endp,
				impl->poll ? 0 : LELY_IO_RX_TIMEOUT);

#if _WIN32
	SOCKET sListenSocket = handle->fd;
	SOCKET sAcceptSocket = io_wsa_socket(
			handle->family, SOCK_STREAM, handle->protocol);

	accept->_listen = (HANDLE)sListenSocket;
	accept->_accept = (HANDLE)sAcceptSocket;
	accept->_cp = (struct io_cp)IO_CP_INIT(
			&io_sock_stream_srv_impl_accept_cp_func);

	if (sAcceptSocket == INVALID_SOCKET)
		return INVALID_SOCKET;

	if (!handle->lpfnAcceptEx) {
		WSASetLastError(WSAEOPNOTSUPP);
		return INVALID_SOCKET;
	}

	DWORD dwBytesReceived = 0;
	// clang-format off
	if (!handle->lpfnAcceptEx(sListenSocket, sAcceptSocket, accept->_buf, 0,
			sizeof(struct io_sockaddr_storage) + 16,
			sizeof(struct io_sockaddr_storage) + 16,
			&dwBytesReceived, &accept->_cp.overlapped))
		// clang-format on
		return INVALID_SOCKET;

	return sAcceptSocket;
#endif // _WIN32
}

#if _WIN32
static void
io_sock_stream_srv_impl_accept_cp_func(
		struct io_cp *cp, size_t nbytes, int errc)
{
	assert(cp);
	struct io_sock_stream_srv_accept *accept =
			structof(cp, struct io_sock_stream_srv_accept, _cp);
	assert(accept->sock);
	struct io_sock_stream_impl *impl = structof(accept->sock,
			struct io_sock_stream_impl, sock_stream_vptr);

	int iError = WSAGetLastError();

	SOCKET sListenSocket = (SOCKET)accept->_listen;
	SOCKET sAcceptSocket = (SOCKET)accept->_accept;

	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	handle.fd = sAcceptSocket;

	DWORD cbTransfer = nbytes;
	DWORD dwFlags = 0;
	// clang-format off
	if (WSAGetOverlappedResult(sListenSocket, &cp->overlapped, &cbTransfer,
			FALSE, &dwFlags))
		// clang-format on
		nbytes = cbTransfer;
	else
		errc = WSAGetLastError();

	if (errc)
		goto error;

	// clang-format off
	if (setsockopt(sAcceptSocket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
			(char *)&sListenSocket, sizeof(sListenSocket))
			== SOCKET_ERROR) {
		// clang-format on
		errc = WSAGetLastError();
		goto error;
	}

	// clang-format off
	if (accept->endp && io_sock_fd_getpeername(sAcceptSocket,
			impl->endp_vptr, accept->endp) == -1) {
		// clang-format on
		errc = WSAGetLastError();
		goto error;
	}

error:
	io_sock_stream_srv_impl_accept_post(accept, &handle, errc);

	WSASetLastError(iError);
}
#endif // _WIN32

static void
io_sock_stream_srv_impl_accept_post(struct io_sock_stream_srv_accept *accept,
		const struct io_sock_stream_handle *handle, int errc)
{
	assert(accept);
	assert(accept->sock);
	struct io_sock_stream_impl *impl = structof(accept->sock,
			struct io_sock_stream_impl, sock_stream_vptr);
	assert(handle);

#if _WIN32
	struct io_sock_stream_srv_impl *srv_impl = accept->task._data;
	accept->task._data = NULL;
	// Remove the task from the queue, unless it was canceled.
	if (srv_impl && errc != ERROR_OPERATION_ABORTED) {
		assert(srv_impl->poll);
#if !LELY_NO_THREADS
		mtx_lock(&srv_impl->mtx);
#endif
		sllist_remove(&srv_impl->accept_iocp_queue,
				&accept->task._node);
#if !LELY_NO_THREADS
		mtx_unlock(&srv_impl->mtx);
#endif
	}
#endif

	if (errc)
		goto error;

	if (io_sock_stream_impl_assign(impl, handle) == -1) {
		errc = WSAGetLastError();
		goto error;
	}
	handle = NULL;

error:
	if (handle && handle->fd != INVALID_SOCKET)
		closesocket(handle->fd);
	io_sock_stream_srv_accept_post(accept, errc);
}

static inline struct io_sock_stream_srv_impl *
io_sock_stream_srv_impl_from_dev(const io_dev_t *dev)
{
	assert(dev);

	return structof(dev, struct io_sock_stream_srv_impl, dev_vptr);
}

static inline struct io_sock_stream_srv_impl *
io_sock_stream_srv_impl_from_sock(const io_sock_t *sock)
{
	assert(sock);

	return structof(sock, struct io_sock_stream_srv_impl, sock_vptr);
}

static inline struct io_sock_stream_srv_impl *
io_sock_stream_srv_impl_from_sock_stream_srv(
		const io_sock_stream_srv_t *sock_stream_srv)
{
	assert(sock_stream_srv);

	return structof(sock_stream_srv, struct io_sock_stream_srv_impl,
			sock_stream_srv_vptr);
}

static inline struct io_sock_stream_srv_impl *
io_sock_stream_srv_impl_from_svc(const struct io_svc *svc)
{
	assert(svc);

	return structof(svc, struct io_sock_stream_srv_impl, svc);
}

static void
io_sock_stream_srv_impl_do_pop(struct io_sock_stream_srv_impl *impl,
		struct sllist *wait_queue, struct sllist *accept_queue,
		struct ev_task *task)
{
	assert(impl);
	assert(wait_queue);
	assert(accept_queue);

	if (!task) {
		sllist_append(wait_queue, &impl->wait_queue);
		sllist_append(accept_queue, &impl->accept_queue);
	} else if (sllist_remove(&impl->wait_queue, &task->_node)) {
		sllist_push_back(wait_queue, &task->_node);
	} else if (sllist_remove(&impl->accept_queue, &task->_node)) {
		sllist_push_back(accept_queue, &task->_node);
	}
}

#if _WIN32
static size_t
io_sock_stream_srv_impl_do_cancel_iocp(
		struct io_sock_stream_srv_impl *impl, struct ev_task *task)
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

	// Try to cancel matching accept operations waiting for a completion
	// packet.
	for (struct slnode **pnode = &impl->accept_iocp_queue.first; *pnode;
			pnode = &(*pnode)->next) {
		struct io_sock_stream_srv_accept *accept =
				io_sock_stream_srv_accept_from_task(
						ev_task_from_node(*pnode));
		if (task && task != &accept->task)
			continue;
		// CancelIoEx() only works with the base service provider
		// handle.
		SOCKET s = io_wsa_base_handle((SOCKET)accept->_listen);
		if (s == INVALID_SOCKET)
			continue;
		if (!CancelIoEx((HANDLE)s, &accept->_cp.overlapped))
			continue;
		n += n < SIZE_MAX;
		// Remove the task from the queue.
		if (!(*pnode = (*pnode)->next)) {
			impl->accept_iocp_queue.plast = pnode;
			break;
		}
	}

	SetLastError(dwErrCode);
	return n;
}
#endif // _WIN32

static size_t
io_sock_stream_srv_do_abort_tasks(struct io_sock_stream_srv_impl *impl)
{
	assert(impl);

	size_t n = 0;

	// Try to abort io_sock_stream_srv_impl_wait_task_func().
	// clang-format off
	if (impl->wait_posted && ev_exec_abort(impl->wait_task.exec,
			&impl->wait_task)) {
		// clang-format on
		impl->wait_posted = 0;
		n++;
	}

	// Try to abort io_sock_stream_srv_impl_accept_task_func().
	// clang-format off
	if (impl->accept_posted && ev_exec_abort(impl->accept_task.exec,
			&impl->accept_task)) {
		// clang-format on
		impl->accept_posted = 0;
		n++;
	}

	return n;
}

static SOCKET
io_sock_stream_srv_impl_set_handle(struct io_sock_stream_srv_impl *impl,
		const struct io_sock_stream_srv_handle *handle)
{
	assert(impl);
	assert(handle);

#if _WIN32
	LPFN_ACCEPTEX lpfnAcceptEx = NULL;
	int iError = WSAGetLastError();
	if (handle->fd != INVALID_SOCKET
			&& !(lpfnAcceptEx = io_wsa_get_acceptex(handle->fd)))
		// Ignore the error here since we cannot handle it. We notify
		// the user on the first asynchronous accept attempt.
		WSASetLastError(iError);
#endif

	struct sllist wait_queue, accept_queue;
	sllist_init(&wait_queue);
	sllist_init(&accept_queue);

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
	impl->handle.lpfnAcceptEx = lpfnAcceptEx;
#endif

	// Cancel pending operations.
	sllist_append(&wait_queue, &impl->wait_queue);
	sllist_append(&accept_queue, &impl->accept_queue);

#if _WIN32
	// Cancel operations waiting for a completion packet.
	io_sock_stream_srv_impl_do_cancel_iocp(impl, NULL);
#endif

	// Mark the ongoing accept operation as canceled, if necessary.
	impl->current_accept = NULL;

#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif

	io_sock_wait_queue_post(
			&wait_queue, IO_EVENT_ERR, ERROR_OPERATION_ABORTED);
	io_sock_stream_srv_accept_queue_post(
			&accept_queue, ERROR_OPERATION_ABORTED);

	return fd;
}

#endif // _WIN32 || (_POSIX_C_SOURCE && !__NEWLIB__)
