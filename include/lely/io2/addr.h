/**@file
 * This header file is part of the I/O library; it contains the network address
 * declarations.
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

#ifndef LELY_IO2_ADDR_H_
#define LELY_IO2_ADDR_H_

#include <lely/features.h>

/// An unspecified network address.
#define IO_ADDR_UNSPEC 0

/// A struct containing the common initial sequence of network addresses.
struct io_addr {
	/// The result of the `sizeof` operator applied to the address.
	unsigned short len;
	/**
	 * The network address family (one of #IO_ADDR_UNSPEC, IO_ADDR_IPV4,
	 * #IO_ADDR_IPV6 or #IO_ADDR_BTH).
	 */
	unsigned short family;
};

/// The static initializer for #io_addr.
#define IO_ADDR_INIT \
	{ \
		sizeof(struct io_addr), IO_ADDR_UNSPEC \
	}

#endif // !LELY_IO2_ADDR_H_
