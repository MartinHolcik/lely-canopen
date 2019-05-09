/**@file
 * This file is part of the I/O library; it contains the Bluetooth RFCOMM socket
 * implementation for Windows.
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

#if _WIN32

#include <lely/io2/sys/rfcomm.h>
#include <lely/util/errnum.h>
#include <lely/util/util.h>

#include <assert.h>
#include <stdlib.h>

#include <ws2bth.h>

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
	if (!impl) {
		set_errc(errno2c(errno));
		return NULL;
	}
	return &impl->rfcomm_srv_vptr;
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
	DWORD dwErrCode = 0;

	io_rfcomm_srv_t *rfcomm = io_rfcomm_srv_alloc();
	if (!rfcomm) {
		dwErrCode = GetLastError();
		goto error_alloc;
	}

	io_rfcomm_srv_t *tmp = io_rfcomm_srv_init(rfcomm, poll, exec);
	if (!tmp) {
		dwErrCode = GetLastError();
		goto error_init;
	}
	rfcomm = tmp;

	return rfcomm;

error_init:
	io_rfcomm_srv_free((void *)rfcomm);
error_alloc:
	SetLastError(dwErrCode);
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

SOCKET
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
io_rfcomm_srv_assign(io_rfcomm_srv_t *rfcomm, SOCKET s)
{
	struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_rfcomm_srv(rfcomm);

	struct io_sock_stream_srv_handle handle =
			IO_SOCK_STREAM_SRV_HANDLE_INIT;
	handle.fd = s;

	WSAPROTOCOL_INFOA ProtocolInfo = { .iAddressFamily = AF_UNSPEC };
	// clang-format off
	if (getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFOA, (char *)&ProtocolInfo,
			&(int){ sizeof(ProtocolInfo) }) == SOCKET_ERROR)
		// clang-format on
		return -1;

	handle.family = ProtocolInfo.iAddressFamily;
	if (handle.family != AF_BTH) {
		WSASetLastError(WSAEAFNOSUPPORT);
		return -1;
	}

	handle.protocol = ProtocolInfo.iProtocol;
	if (handle.protocol != BTHPROTO_RFCOMM) {
		WSASetLastError(WSAEPROTONOSUPPORT);
		return -1;
	}

	return io_sock_stream_srv_impl_assign(impl, &handle);
}

SOCKET
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
	if (!impl) {
		set_errc(errno2c(errno));
		return NULL;
	}
	return &impl->rfcomm_vptr;
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
	DWORD dwErrCode = 0;

	io_rfcomm_t *rfcomm = io_rfcomm_alloc();
	if (!rfcomm) {
		dwErrCode = GetLastError();
		goto error_alloc;
	}

	io_rfcomm_t *tmp = io_rfcomm_init(rfcomm, poll, exec);
	if (!tmp) {
		dwErrCode = GetLastError();
		goto error_init;
	}
	rfcomm = tmp;

	return rfcomm;

error_init:
	io_rfcomm_free((void *)rfcomm);
error_alloc:
	SetLastError(dwErrCode);
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

SOCKET
io_rfcomm_get_handle(const io_rfcomm_t *rfcomm)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_rfcomm(rfcomm), &handle);

	return handle.fd;
}

int
io_rfcomm_assign(io_rfcomm_t *rfcomm, SOCKET s)
{
	struct io_sock_stream_impl *impl =
			io_sock_stream_impl_from_rfcomm(rfcomm);

	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	handle.fd = s;

	WSAPROTOCOL_INFOA ProtocolInfo = { .iAddressFamily = AF_UNSPEC };
	// clang-format off
	if (getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFOA, (char *)&ProtocolInfo,
			&(int){ sizeof(ProtocolInfo) }) == SOCKET_ERROR)
		// clang-format on
		return -1;

	handle.family = ProtocolInfo.iAddressFamily;
	if (handle.family != AF_BTH) {
		WSASetLastError(WSAEAFNOSUPPORT);
		return -1;
	}

	handle.protocol = ProtocolInfo.iProtocol;
	if (handle.protocol != BTHPROTO_RFCOMM) {
		WSASetLastError(WSAEPROTONOSUPPORT);
		return -1;
	}

	return io_sock_stream_impl_assign(impl, &handle);
}

SOCKET
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
	return io_sock_stream_srv_impl_open(impl, AF_BTH, BTHPROTO_RFCOMM)
			!= INVALID_SOCKET ? 0 : -1;
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
	return io_sock_stream_impl_open(impl, AF_BTH, BTHPROTO_RFCOMM)
			!= INVALID_SOCKET ? 0 : -1;
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

	if (addr->sa_family != AF_BTH) {
		WSASetLastError(WSAEAFNOSUPPORT);
		return -1;
	}

	if (addrlen != sizeof(SOCKADDR_BTH)) {
		WSASetLastError(WSAEINVAL);
		return -1;
	}
	const SOCKADDR_BTH *addr_bth = (const SOCKADDR_BTH *)addr;

	int len = (int)sizeof(struct io_endp_bth_rfcomm);
	if ((endp->addr && endp->addr->family != IO_ADDR_BTH)
			|| endp->len < len) {
		WSASetLastError(WSAEINVAL);
		return -1;
	}
	struct io_endp_bth_rfcomm *bth_rfcomm =
			(struct io_endp_bth_rfcomm *)endp;
	*bth_rfcomm = (struct io_endp_bth_rfcomm)IO_ENDP_BTH_RFCOMM_INIT(
			bth_rfcomm);

	io_addr_bth_set_from_uint(&bth_rfcomm->bth, addr_bth->btAddr);
	bth_rfcomm->channel =
			addr_bth->port != BT_PORT_ANY ? addr_bth->port : 0;

	return 0;
}

static int
io_rfcomm_endp_store(const struct io_endp *endp, struct sockaddr *addr,
		socklen_t *addrlen)
{
	assert(endp);
	assert(addr);
	assert(addrlen);

	if (!endp->addr || endp->addr->family != IO_ADDR_BTH) {
		WSASetLastError(WSAEAFNOSUPPORT);
		return -1;
	}

	if (endp->len != sizeof(struct io_endp_bth_rfcomm)
			|| endp->protocol != IO_BTHPROTO_RFCOMM) {
		WSASetLastError(WSAEINVAL);
		return -1;
	}
	const struct io_endp_bth_rfcomm *bth_rfcomm =
			(const struct io_endp_bth_rfcomm *)endp;

	if (*addrlen < (socklen_t)sizeof(SOCKADDR_BTH)) {
		WSASetLastError(WSAEINVAL);
		return -1;
	}
	*addrlen = sizeof(SOCKADDR_BTH);
	SOCKADDR_BTH *addr_bth = (SOCKADDR_BTH *)addr;
	*addr_bth = (SOCKADDR_BTH){ .addressFamily = AF_BTH };

	addr_bth->btAddr = io_addr_bth_to_uint(&bth_rfcomm->bth);
	addr_bth->port =
			bth_rfcomm->channel ? bth_rfcomm->channel : BT_PORT_ANY;

	return 0;
}

static int
io_rfcomm_endp_store_any(int family, int protocol, SOCKADDR *addr, int *addrlen)
{
	assert(addr);
	assert(addrlen);

	if (family == AF_BTH) {
		WSASetLastError(WSAEAFNOSUPPORT);
		return -1;
	}

	if (protocol != BTHPROTO_RFCOMM) {
		WSASetLastError(WSAEINVAL);
		return -1;
	}

	if (*addrlen < (socklen_t)sizeof(SOCKADDR_BTH)) {
		WSASetLastError(WSAEINVAL);
		return -1;
	}

	*addrlen = sizeof(SOCKADDR_BTH);
	SOCKADDR_BTH *addr_bth = (SOCKADDR_BTH *)addr;
	*addr_bth = (SOCKADDR_BTH){
		.addressFamily = AF_BTH, .btAddr = 0, .port = BT_PORT_ANY
	};

	return 0;
}

#endif // _WIN32
