/**@file
 * This header file is part of the I/O library; it contains the network protocol
 * endpoint declarations.
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

#ifndef LELY_IO2_ENDP_H_
#define LELY_IO2_ENDP_H_

#include <lely/io2/addr.h>

#include <stddef.h>

/**
 * A struct containing the common initial sequence of network protocol
 * endpoints.
 */
struct io_endp {
	/// A pointer to the network address.
	struct io_addr *addr;
	/// The result of the `sizeof` operator applied to the endpoint.
	int len;
	/**
	 * The network protocol identifier. The interpretation of the value of
	 * <b>protocol</b> MAY depend on the network address family (see, the
	 * <b>family</b> member at #addr).
	 */
	int protocol;
};

/**
 * The size (in bytes) of a network endpoint large enough to accommodate all
 * supported protocol-specific endpoints.
 */
#define IO_ENDP_STORAGE_SIZE 128

/**
 * An network endpoint large enough to accommodate all supported
 * protocol-specific endpoints.
 */
struct io_endp_storage {
	/// `NULL`
	struct io_addr *addr;
	/// #IO_ENDP_STORAGE_SIZE
	int len;
	/// `0`
	int protocol;
	char _pad[IO_ENDP_STORAGE_SIZE - sizeof(struct io_endp)
			- sizeof(long long)];
	long long _align;
};

/// The static initializer for #io_endp_storage.
#define IO_ENDP_STORAGE_INIT \
	{ \
		NULL, sizeof(struct io_endp_storage), 0, { 0 }, 0 \
	}

#if _WIN32 || defined(_POSIX_C_SOURCE)

/// The size (in bytes) of #io_sockaddr_storage.
#define IO_SOCKADDR_STORAGE_SIZE 128

/**
 * A struct large enough to accomodate all socket addresses of the Berkely
 * sockets API. This struct is compatible with `struct sockaddr_storage` on
 * Windows and POSIX plarforms.
 */
struct io_sockaddr_storage {
	short ss_family;
	char _pad[IO_SOCKADDR_STORAGE_SIZE - sizeof(short) - sizeof(long long)];
	long long _align;
};

/// The static initializer for #io_sockaddr_storage.
#define IO_SOCKADDR_STORAGE_INIT \
	{ \
		0, { 0 }, 0 \
	}

#endif // _WIN32 || _POSIX_C_SOURCE

#endif // !LELY_IO2_ENDP_H_
