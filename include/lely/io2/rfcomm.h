/**@file
 * This header file is part of the I/O library; it contains the Bluetooth RFCOMM
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

#ifndef LELY_IO2_RFCOMM_H_
#define LELY_IO2_RFCOMM_H_

#include <lely/io2/bth.h>
#include <lely/io2/endp.h>

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

#endif // !LELY_IO2_RFCOMM_H_
