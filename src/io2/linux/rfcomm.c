/**@file
 * This file is part of the I/O library; it contains the Bluetooth RFCOMM socket
 * implementation for Linux.
 *
 * @see lely/io2/sys/rfcomm.h
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

#include "io.h"

#if defined(__linux__) && LELY_HAVE_BLUEZ

#include <lely/io2/sys/rfcomm.h>
#include <lely/util/util.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>

#include "../sys/sock_stream.h"
#include "../sys/sock_stream_srv.h"

static io_sock_stream_srv_t *io_rfcomm_srv_impl_get_sock_stream_srv(
		const io_rfcomm_srv_t *rfcomm);
static int io_rfcomm_srv_impl_open(io_rfcomm_srv_t *rfcomm);

// clang-format off
static const struct io_rfcomm_srv_vtbl io_rfcomm_srv_impl_vtbl = {
	&io_rfcomm_srv_impl_get_sock_stream_srv,
	&io_rfcomm_srv_impl_open
};
// clang-format on

/// The implementation of a Bluetooth RFCOMM server.
struct io_rfcomm_srv_impl {
	/**
	 * A pointer to the virtual table for the Bluetooth RFCOMM server
	 * interface.
	 */
	const struct io_rfcomm_srv_vtbl *rfcomm_srv_vptr;
	/// The stream server.
	struct io_sock_stream_srv_impl sock_stream_srv_impl;
};

static inline struct io_rfcomm_srv_impl *io_rfcomm_srv_impl_from_rfcomm_srv(
		const io_rfcomm_srv_t *rfcomm);
static inline struct io_sock_stream_srv_impl *
io_sock_stream_srv_impl_from_rfcomm_srv(const io_rfcomm_srv_t *rfcomm);

static io_sock_stream_t *io_rfcomm_impl_get_sock_stream(
		const io_rfcomm_t *rfcomm);
static int io_rfcomm_impl_open(io_rfcomm_t *rfcomm);

// clang-format off
static const struct io_rfcomm_vtbl io_rfcomm_impl_vtbl = {
	&io_rfcomm_impl_get_sock_stream,
	&io_rfcomm_impl_open
};
// clang-format on

/// The implementation of a Bluetooth RFCOMM socket.
struct io_rfcomm_impl {
	/**
	 * A pointer to the virtual table for the Bluetooth RFCOMM socket
	 * interface.
	 */
	const struct io_rfcomm_vtbl *rfcomm_vptr;
	/// The stream server.
	struct io_sock_stream_impl sock_stream_impl;
};

static inline struct io_rfcomm_impl *io_rfcomm_impl_from_rfcomm(
		const io_rfcomm_t *rfcomm);
static inline struct io_sock_stream_impl *io_sock_stream_impl_from_rfcomm(
		const io_rfcomm_t *rfcomm);

static int io_rfcomm_endp_load(struct io_endp *endp,
		const struct sockaddr *addr, socklen_t addrlen);
static int io_rfcomm_endp_store(const struct io_endp *endp,
		struct sockaddr *addr, socklen_t *addrlen);
static int io_rfcomm_endp_store_any(int family, int protocol,
		struct sockaddr *addr, socklen_t *addrlen);

// clang-format off
static const struct io_endp_vtbl io_rfcomm_endp_vtbl = {
	&io_rfcomm_endp_load,
	&io_rfcomm_endp_store,
	&io_rfcomm_endp_store_any
};
// clang-format on

void *
io_rfcomm_srv_alloc(void)
{
	struct io_rfcomm_srv_impl *impl = malloc(sizeof(*impl));
	return impl ? &impl->rfcomm_srv_vptr : NULL;
}

void
io_rfcomm_srv_free(void *ptr)
{
	if (ptr)
		free(io_rfcomm_srv_impl_from_rfcomm_srv(ptr));
}

io_rfcomm_srv_t *
io_rfcomm_srv_init(io_rfcomm_srv_t *rfcomm, io_poll_t *poll, ev_exec_t *exec)
{
	io_rfcomm_srv_impl_from_rfcomm_srv(rfcomm)->rfcomm_srv_vptr =
			&io_rfcomm_srv_impl_vtbl;
	struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_rfcomm_srv(rfcomm);

	// clang-format off
	return !io_sock_stream_srv_impl_init(impl, poll, exec,
			&io_rfcomm_endp_vtbl) ? rfcomm : NULL;
	// clang-format on
}

void
io_rfcomm_srv_fini(io_rfcomm_srv_t *rfcomm)
{
	struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_rfcomm_srv(rfcomm);

	io_sock_stream_srv_impl_fini(impl);
}

io_rfcomm_srv_t *
io_rfcomm_srv_create(io_poll_t *poll, ev_exec_t *exec)
{
	int errsv = 0;

	io_rfcomm_srv_t *rfcomm = io_rfcomm_srv_alloc();
	if (!rfcomm) {
		errsv = errno;
		goto error_alloc;
	}

	io_rfcomm_srv_t *tmp = io_rfcomm_srv_init(rfcomm, poll, exec);
	if (!tmp) {
		errsv = errno;
		goto error_init;
	}
	rfcomm = tmp;

	return rfcomm;

error_init:
	io_rfcomm_srv_free((void *)rfcomm);
error_alloc:
	errno = errsv;
	return NULL;
}

void
io_rfcomm_srv_destroy(io_rfcomm_srv_t *rfcomm)
{
	if (rfcomm) {
		io_rfcomm_srv_fini(rfcomm);
		io_rfcomm_srv_free((void *)rfcomm);
	}
}

int
io_rfcomm_srv_get_handle(const io_rfcomm_srv_t *rfcomm)
{
	struct io_sock_stream_srv_handle handle =
			IO_SOCK_STREAM_SRV_HANDLE_INIT;
	io_sock_stream_srv_impl_get_handle(
			io_sock_stream_srv_impl_from_rfcomm_srv(rfcomm),
			&handle);

	return handle.fd;
}

int
io_rfcomm_srv_assign(io_rfcomm_srv_t *rfcomm, int fd)
{
	struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_rfcomm_srv(rfcomm);

	struct io_sock_stream_srv_handle handle =
			IO_SOCK_STREAM_SRV_HANDLE_INIT;
	handle.fd = fd;

	handle.family = AF_BLUETOOTH;
	// clang-format off
	if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &handle.family,
			&(socklen_t){ sizeof(handle.family) }) == -1)
		// clang-format on
		return -1;

	if (handle.family != AF_BLUETOOTH) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	handle.protocol = BTPROTO_RFCOMM;
	// clang-format off
	if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &handle.protocol,
			&(socklen_t){ sizeof(handle.protocol) }) == -1)
		// clang-format on
		return -1;

	if (handle.protocol != BTPROTO_RFCOMM) {
		errno = EPROTONOSUPPORT;
		return -1;
	}

	return io_sock_stream_srv_impl_assign(impl, &handle);
}

int
io_rfcomm_srv_release(io_rfcomm_srv_t *rfcomm)
{
	struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_rfcomm_srv(rfcomm);

	return io_sock_stream_srv_impl_release(impl);
}

void *
io_rfcomm_alloc(void)
{
	struct io_rfcomm_impl *impl = malloc(sizeof(*impl));
	return impl ? &impl->rfcomm_vptr : NULL;
}

void
io_rfcomm_free(void *ptr)
{
	if (ptr)
		free(io_rfcomm_impl_from_rfcomm(ptr));
}

io_rfcomm_t *
io_rfcomm_init(io_rfcomm_t *rfcomm, io_poll_t *poll, ev_exec_t *exec)
{
	io_rfcomm_impl_from_rfcomm(rfcomm)->rfcomm_vptr = &io_rfcomm_impl_vtbl;
	struct io_sock_stream_impl *impl =
			io_sock_stream_impl_from_rfcomm(rfcomm);

	return !io_sock_stream_impl_init(impl, poll, exec, &io_rfcomm_endp_vtbl)
			? rfcomm
			: NULL;
}

void
io_rfcomm_fini(io_rfcomm_t *rfcomm)
{
	struct io_sock_stream_impl *impl =
			io_sock_stream_impl_from_rfcomm(rfcomm);

	io_sock_stream_impl_fini(impl);
}

io_rfcomm_t *
io_rfcomm_create(io_poll_t *poll, ev_exec_t *exec)
{
	int errsv = 0;

	io_rfcomm_t *rfcomm = io_rfcomm_alloc();
	if (!rfcomm) {
		errsv = errno;
		goto error_alloc;
	}

	io_rfcomm_t *tmp = io_rfcomm_init(rfcomm, poll, exec);
	if (!tmp) {
		errsv = errno;
		goto error_init;
	}
	rfcomm = tmp;

	return rfcomm;

error_init:
	io_rfcomm_free((void *)rfcomm);
error_alloc:
	errno = errsv;
	return NULL;
}

void
io_rfcomm_destroy(io_rfcomm_t *rfcomm)
{
	if (rfcomm) {
		io_rfcomm_fini(rfcomm);
		io_rfcomm_free((void *)rfcomm);
	}
}

int
io_rfcomm_get_handle(const io_rfcomm_t *rfcomm)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_rfcomm(rfcomm), &handle);

	return handle.fd;
}

int
io_rfcomm_assign(io_rfcomm_t *rfcomm, int fd)
{
	struct io_sock_stream_impl *impl =
			io_sock_stream_impl_from_rfcomm(rfcomm);

	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	handle.fd = fd;

	handle.family = AF_BLUETOOTH;
	// clang-format off
	if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &handle.family,
			&(socklen_t){ sizeof(handle.family) }) == -1)
		// clang-format on
		return -1;

	if (handle.family != AF_BLUETOOTH) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	handle.protocol = BTPROTO_RFCOMM;
	// clang-format off
	if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &handle.protocol,
			&(socklen_t){ sizeof(handle.protocol) }) == -1)
		// clang-format on
		return -1;

	if (handle.protocol != BTPROTO_RFCOMM) {
		errno = EPROTONOSUPPORT;
		return -1;
	}

	return io_sock_stream_impl_assign(impl, &handle);
}

int
io_rfcomm_release(io_rfcomm_t *rfcomm)
{
	struct io_sock_stream_impl *impl =
			io_sock_stream_impl_from_rfcomm(rfcomm);

	return io_sock_stream_impl_release(impl);
}

static io_sock_stream_srv_t *
io_rfcomm_srv_impl_get_sock_stream_srv(const io_rfcomm_srv_t *rfcomm)
{
	const struct io_rfcomm_srv_impl *impl =
			io_rfcomm_srv_impl_from_rfcomm_srv(rfcomm);

	return &impl->sock_stream_srv_impl.sock_stream_srv_vptr;
}

static int
io_rfcomm_srv_impl_open(io_rfcomm_srv_t *rfcomm)
{
	struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_rfcomm_srv(rfcomm);

	// clang-format off
	return io_sock_stream_srv_impl_open(impl, AF_BLUETOOTH, BTPROTO_RFCOMM)
			!= -1 ? 0 : -1;
	// clang-format on
}

static inline struct io_rfcomm_srv_impl *
io_rfcomm_srv_impl_from_rfcomm_srv(const io_rfcomm_srv_t *rfcomm)
{
	assert(rfcomm);

	return structof(rfcomm, struct io_rfcomm_srv_impl, rfcomm_srv_vptr);
}

static inline struct io_sock_stream_srv_impl *
io_sock_stream_srv_impl_from_rfcomm_srv(const io_rfcomm_srv_t *rfcomm)
{
	return &io_rfcomm_srv_impl_from_rfcomm_srv(rfcomm)
				->sock_stream_srv_impl;
}

static io_sock_stream_t *
io_rfcomm_impl_get_sock_stream(const io_rfcomm_t *rfcomm)
{
	const struct io_rfcomm_impl *impl = io_rfcomm_impl_from_rfcomm(rfcomm);

	return &impl->sock_stream_impl.sock_stream_vptr;
}

static int
io_rfcomm_impl_open(io_rfcomm_t *rfcomm)
{
	struct io_sock_stream_impl *impl =
			io_sock_stream_impl_from_rfcomm(rfcomm);

	// clang-format off
	return io_sock_stream_impl_open(impl, AF_BLUETOOTH, BTPROTO_RFCOMM)
			!= -1 ? 0 : -1;
	// clang-format on
}

static inline struct io_rfcomm_impl *
io_rfcomm_impl_from_rfcomm(const io_rfcomm_t *rfcomm)
{
	assert(rfcomm);

	return structof(rfcomm, struct io_rfcomm_impl, rfcomm_vptr);
}

static inline struct io_sock_stream_impl *
io_sock_stream_impl_from_rfcomm(const io_rfcomm_t *rfcomm)
{
	return &io_rfcomm_impl_from_rfcomm(rfcomm)->sock_stream_impl;
}

static int
io_rfcomm_endp_load(struct io_endp *endp, const struct sockaddr *addr,
		socklen_t addrlen)
{
	assert(endp);
	assert(addr);

	if (addr->sa_family != AF_BLUETOOTH) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	if (addrlen != sizeof(struct sockaddr_rc)) {
		errno = EINVAL;
		return -1;
	}
	const struct sockaddr_rc *addr_rc = (const struct sockaddr_rc *)addr;

	int len = (int)sizeof(struct io_endp_bth_rfcomm);
	if ((endp->addr && endp->addr->family != IO_ADDR_BTH)
			|| endp->len < len) {
		errno = EINVAL;
		return -1;
	}
	struct io_endp_bth_rfcomm *bth_rfcomm =
			(struct io_endp_bth_rfcomm *)endp;
	*bth_rfcomm = (struct io_endp_bth_rfcomm)IO_ENDP_BTH_RFCOMM_INIT(
			bth_rfcomm);

	// Bluez stores the address in little-endian byte order.
	unsigned char bytes[6];
	for (int i = 0; i < 6; i++)
		bytes[i] = addr_rc->rc_bdaddr.b[5 - i];
	io_addr_bth_set_from_bytes(&bth_rfcomm->bth, bytes);
	bth_rfcomm->channel = addr_rc->rc_channel;

	return 0;
}

static int
io_rfcomm_endp_store(const struct io_endp *endp, struct sockaddr *addr,
		socklen_t *addrlen)
{
	assert(endp);
	assert(addr);
	assert(addrlen);

	if (!endp->addr || endp->addr->family == IO_ADDR_BTH) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	if (endp->len != sizeof(struct io_endp_bth_rfcomm)
			|| endp->protocol != IO_BTHPROTO_RFCOMM) {
		errno = EINVAL;
		return -1;
	}
	const struct io_endp_bth_rfcomm *bth_rfcomm =
			(const struct io_endp_bth_rfcomm *)endp;

	if (*addrlen < (socklen_t)sizeof(struct sockaddr_rc)) {
		errno = EINVAL;
		return -1;
	}
	*addrlen = sizeof(struct sockaddr_rc);
	struct sockaddr_rc *addr_rc = (struct sockaddr_rc *)addr;
	*addr_rc = (struct sockaddr_rc){ .rc_family = AF_BLUETOOTH };

	// Bluez stores the address in little-endian byte order.
	for (int i = 0; i < 6; i++)
		addr_rc->rc_bdaddr.b[i] = bth_rfcomm->bth.bytes[5 - i];
	addr_rc->rc_channel = bth_rfcomm->channel;

	return 0;
}

static int
io_rfcomm_endp_store_any(int family, int protocol, struct sockaddr *addr,
		socklen_t *addrlen)
{
	assert(addr);
	assert(addrlen);

	if (family == AF_BLUETOOTH) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	if (protocol != BTPROTO_RFCOMM) {
		errno = EINVAL;
		return -1;
	}

	if (*addrlen < (socklen_t)sizeof(struct sockaddr_rc)) {
		errno = EINVAL;
		return -1;
	}

	*addrlen = sizeof(struct sockaddr_rc);
	struct sockaddr_rc *addr_rc = (struct sockaddr_rc *)addr;
	*addr_rc = (struct sockaddr_rc){ .rc_family = AF_BLUETOOTH };

	return 0;
}

#endif // __linux__ && LELY_HAVE_BLUEZ
