/**@file
 * This is the internal header file of the NMT 'boot slave' declarations.
 *
 * @see lely/co/nmt.h
 *
 * @copyright 2017-2020 Lely Industries N.V.
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

#ifndef LELY_CO_INTERN_NMT_BOOT_H_
#define LELY_CO_INTERN_NMT_BOOT_H_

#include "co.h"
#include <lely/co/csdo.h>
#include <lely/co/nmt.h>

struct co_nmt_boot;
/// An opaque CANopen NMT 'boot slave' service type.
typedef struct co_nmt_boot co_nmt_boot_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The CANopen NMT 'boot slave' confirmation function, invoked when the 'boot
 * slave' process completes.
 *
 * @param nmt a pointer to an NMT master service.
 * @param id  the node-ID of the slave (in the range [1..127]).
 * @param st  the state of the node (including the toggle bit).
 * @param es  the error status (in the range ['A'..'O'], or 0 on success).
 */
void co_nmt_boot_con(
		co_nmt_t *nmt, co_unsigned8_t id, co_unsigned8_t st, char es);

/// Returns the alignment (in bytes) of the #co_nmt_boot_t structure.
size_t co_nmt_boot_alignof(void);

/// Returns the size (in bytes) of the #co_nmt_boot_t structure.
size_t co_nmt_boot_sizeof(void);

/**
 * Creates a new CANopen NMT 'boot slave' service.
 *
 * @param net a pointer to a CAN network.
 * @param dev a pointer to a CANopen device.
 * @param nmt a pointer to an NMT master service.
 * @param id      the node-ID.
 *
 * @returns a pointer to a new 'boot slave' service, or NULL on error.
 *
 * @see co_nmt_boot_destroy()
 */
co_nmt_boot_t *co_nmt_boot_create(can_net_t *net, co_dev_t *dev, co_nmt_t *nmt,
		co_unsigned8_t id);

/// Destroys a CANopen NMT 'boot slave' service. @see co_nmt_boot_create()
void co_nmt_boot_destroy(co_nmt_boot_t *boot);

/*
 * Returns a pointer to the allocator used to allocate the NMT 'boot slave'
 * service.
 *
 * @see can_net_get_alloc()
 */
alloc_t *co_nmt_boot_get_alloc(const co_nmt_boot_t *boot);

/**
 * Starts a CANopen NMT 'boot slave' service.
 *
 * @param boot    a pointer to an NMT 'boot slave' service.
 * @param timeout the SDO timeout (in milliseconds).
 * @param dn_ind  a pointer to the SDO download progress indication function
 *                (can be NULL).
 * @param up_ind  a pointer to the SDO upload progress indication function (can
 *                be NULL).
 * @param data    a pointer to user-specified data (can be NULL). <b>data</b> is
 *                passed as the last parameter to <b>dn_ind</b> and
 *                <b>up_ind</b>.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 */
int co_nmt_boot_boot_req(co_nmt_boot_t *boot, int_least32_t timeout,
		co_csdo_ind_t *dn_ind, co_csdo_ind_t *up_ind, void *data);

/// Aborts a CANopen NMT 'boot slave' process.
void co_nmt_boot_abort_req(co_nmt_boot_t *boot);

#ifdef __cplusplus
}
#endif

#endif // !LELY_CO_INTERN_NMT_BOOT_H_
