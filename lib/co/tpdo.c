/**@file
 * This file is part of the CANopen library; it contains the implementation of
 * the Transmit-PDO functions.
 *
 * The implementation follows CiA 301 version 4.2.0. See section 7.2.2 for the
 * definition of the PDO services and protocols. The following objects determine
 * the behavior of TPDOs:
 * - 1007: Synchronous window length
 * - 1800..19FF: TPDO communication parameter
 * - 1A00..1BFF: TPDO mapping parameter
 * See table 72 for a description of the transmission type in the communication
 * parameters and table 73 for a description of the mapping parameters.
 *
 * @see lely/co/tpdo.h
 *
 * @copyright 2016-2021 Lely Industries N.V.
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

#include "co.h"

#if !LELY_NO_CO_TPDO

#include <lely/co/dev.h>
#include <lely/co/obj.h>
#include <lely/co/sdo.h>
#include <lely/co/tpdo.h>
#include <lely/co/val.h>
#include <lely/util/error.h>
#include <lely/util/time.h>

#include <assert.h>

/// A CANopen Transmit-PDO.
struct co_tpdo {
	/// A pointer to a CAN network interface.
	can_net_t *net;
	/// A pointer to a CANopen device.
	co_dev_t *dev;
	/// The PDO number.
	co_unsigned16_t num;
	/// A flag specifying whether the Transmit-PDO service is stopped.
	bool stopped;
	/// The PDO communication parameter.
	struct co_pdo_comm_par comm;
	/// The PDO mapping parameter.
	struct co_pdo_map_par map;
	/// A pointer to the CAN frame receiver.
	can_recv_t *recv;
	/// A pointer to the CAN timer for events.
	can_timer_t *timer_event;
	/// A pointer to the CAN timer for the synchronous time window.
	can_timer_t *timer_swnd;
	/// A buffered CAN frame, used for RTR-only or event-driven TPDOs.
	struct can_msg msg;
	/// The time at which the next event-driven TPDO may be sent.
	struct timespec inhibit;
	/// A flag indicating the occurrence of an event.
	unsigned int event : 1;
	/// A flag indicating the synchronous time window has expired.
	unsigned int swnd : 1;
	/// The SYNC start value.
	co_unsigned8_t sync;
	/// The SYNC counter value.
	co_unsigned8_t cnt;
	/// The CANopen SDO upload request used for reading sub-objects.
	struct co_sdo_req req;
	/// A pointer to the indication function.
	co_tpdo_ind_t *ind;
	/// A pointer to user-specified data for #ind.
	void *data;
	/// A pointer to the sampling indication function.
	co_tpdo_sample_ind_t *sample_ind;
	/// A pointer to user-specified data for #sample_ind.
	void *sample_data;
};

/// Allocates memory for #co_tpdo_t object using allocator from #can_net_t.
static void *co_tpdo_alloc(can_net_t *net);

/// Frees memory allocated for #co_tpdo_t object.
static void co_tpdo_free(co_tpdo_t *pdo);

/// Initializes #co_tpdo_t object.
static co_tpdo_t *co_tpdo_init(co_tpdo_t *pdo, can_net_t *net, co_dev_t *dev,
		co_unsigned16_t num);

/// Finalizes #co_tpdo_t object.
static void co_tpdo_fini(co_tpdo_t *pdo);

/**
 * Initializes the CAN frame receiver of a Transmit-PDO service. This function
 * is invoked when one of the TPDO communication parameters (objects 1800..19FF)
 * is updated.
 */
static void co_tpdo_init_recv(co_tpdo_t *pdo);

/**
 * Initializes the CAN timer for events of a Transmit-PDO service. This function
 * is invoked when one of the TPDO communication parameters (objects 1800..19FF)
 * is updated.
 */
static void co_tpdo_init_timer_event(co_tpdo_t *pdo);

/**
 * Initializes the CAN timer for the synchronous time window of a Transmit-PDO
 * service.
 */
static void co_tpdo_init_timer_swnd(co_tpdo_t *pdo);

/**
 * The download indication function for (all sub-objects of) CANopen objects
 * 1800..19FF (TPDO communication parameter).
 *
 * @see co_sub_dn_ind_t
 */
static co_unsigned32_t co_1800_dn_ind(co_sub_t *sub, struct co_sdo_req *req,
		co_unsigned32_t ac, void *data);

/**
 * The download indication function for (all sub-objects of) CANopen objects
 * 1A00..1BFF (TPDO mapping parameter).
 *
 * @see co_sub_dn_ind_t
 */
static co_unsigned32_t co_1a00_dn_ind(co_sub_t *sub, struct co_sdo_req *req,
		co_unsigned32_t ac, void *data);

/**
 * The CAN receive callback function for a Transmit-PDO service.
 *
 * @see can_recv_func_t
 */
static int co_tpdo_recv(const struct can_msg *msg, void *data);

/**
 * The CAN timer callback function for events of a Transmit-PDO service.
 *
 * @see can_timer_func_t
 */
static int co_tpdo_timer_event(const struct timespec *tp, void *data);

/**
 * The CAN timer callback function for the synchronous time window of a
 * Transmit-PDO service.
 *
 * @see can_timer_func_t
 */
static int co_tpdo_timer_swnd(const struct timespec *tp, void *data);

/// The default sampling indication function. @see co_tpdo_sample_ind_t
static int default_sample_ind(co_tpdo_t *pdo, void *data);

/**
 * Initializes a CAN frame to be sent by a Transmit-PDO service.
 *
 * @param pdo a pointer to a Transmit-PDO service.
 * @param msg a pointer to the CAN frame to be initialized.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the indication
 * function is invoked.
 */
static int co_tpdo_init_frame(co_tpdo_t *pdo, struct can_msg *msg);

/**
 * Sends a CAN frame from a Transmit-PDO service and invokes the indication
 * function.
 *
 * @param pdo a pointer to a Transmit-PDO service.
 * @param msg a pointer to the CAN frame to be sent.

 * @return 0 on success, or -1 on error.
 */
static int co_tpdo_send_frame(co_tpdo_t *pdo, const struct can_msg *msg);

size_t
co_tpdo_alignof(void)
{
	return _Alignof(co_tpdo_t);
}

size_t
co_tpdo_sizeof(void)
{
	return sizeof(co_tpdo_t);
}

co_tpdo_t *
co_tpdo_create(can_net_t *net, co_dev_t *dev, co_unsigned16_t num)
{
	trace("creating Transmit-PDO %d", num);

	int errc = 0;

	co_tpdo_t *pdo = co_tpdo_alloc(net);
	if (!pdo) {
		errc = get_errc();
		goto error_alloc_pdo;
	}

	if (!co_tpdo_init(pdo, net, dev, num)) {
		errc = get_errc();
		goto error_init_pdo;
	}

	return pdo;

error_init_pdo:
	co_tpdo_free(pdo);
error_alloc_pdo:
	set_errc(errc);
	return NULL;
}

void
co_tpdo_destroy(co_tpdo_t *tpdo)
{
	if (tpdo) {
		trace("destroying Transmit-PDO %d", tpdo->num);
		co_tpdo_fini(tpdo);
		co_tpdo_free(tpdo);
	}
}

void
co_tpdo_start(co_tpdo_t *pdo)
{
	assert(pdo);

	if (!pdo->stopped)
		return;

	co_obj_t *obj_1800 = co_dev_find_obj(pdo->dev, 0x1800 + pdo->num - 1);
	assert(obj_1800);
	// Copy the PDO communication parameter record.
	memcpy(&pdo->comm, co_obj_addressof_val(obj_1800),
			MIN(co_obj_sizeof_val(obj_1800), sizeof(pdo->comm)));
	// Set the download indication functions PDO communication parameter
	// record.
	co_obj_set_dn_ind(obj_1800, &co_1800_dn_ind, pdo);

	co_obj_t *obj_1a00 = co_dev_find_obj(pdo->dev, 0x1a00 + pdo->num - 1);
	assert(obj_1a00);
	// Copy the PDO mapping parameter record.
	memcpy(&pdo->map, co_obj_addressof_val(obj_1a00),
			MIN(co_obj_sizeof_val(obj_1a00), sizeof(pdo->map)));
	// Set the download indication functions PDO mapping parameter record.
	co_obj_set_dn_ind(obj_1a00, &co_1a00_dn_ind, pdo);

	can_net_get_time(pdo->net, &pdo->inhibit);
	pdo->event = 0;
	pdo->swnd = 1;
	pdo->sync = pdo->comm.sync;
	pdo->cnt = 0;

	co_tpdo_init_recv(pdo);
	co_tpdo_init_timer_event(pdo);

	pdo->stopped = false;
}

void
co_tpdo_stop(co_tpdo_t *pdo)
{
	assert(pdo);

	if (pdo->stopped)
		return;

	can_timer_stop(pdo->timer_swnd);
	can_timer_stop(pdo->timer_event);

	can_recv_stop(pdo->recv);

	// Remove the download indication functions PDO mapping parameter
	// record.
	co_obj_t *obj_1a00 = co_dev_find_obj(pdo->dev, 0x1a00 + pdo->num - 1);
	assert(obj_1a00);
	co_obj_set_dn_ind(obj_1a00, NULL, NULL);

	// Remove the download indication functions PDO communication parameter
	// record.
	co_obj_t *obj_1800 = co_dev_find_obj(pdo->dev, 0x1800 + pdo->num - 1);
	assert(obj_1800);
	co_obj_set_dn_ind(obj_1800, NULL, NULL);

	pdo->stopped = true;
}

bool
co_tpdo_is_stopped(const co_tpdo_t *pdo)
{
	assert(pdo);

	return pdo->stopped;
}

alloc_t *
co_tpdo_get_alloc(const co_tpdo_t *pdo)
{
	assert(pdo);

	return can_net_get_alloc(pdo->net);
}

can_net_t *
co_tpdo_get_net(const co_tpdo_t *pdo)
{
	assert(pdo);

	return pdo->net;
}

co_dev_t *
co_tpdo_get_dev(const co_tpdo_t *pdo)
{
	assert(pdo);

	return pdo->dev;
}

co_unsigned16_t
co_tpdo_get_num(const co_tpdo_t *pdo)
{
	assert(pdo);

	return pdo->num;
}

const struct co_pdo_comm_par *
co_tpdo_get_comm_par(const co_tpdo_t *pdo)
{
	assert(pdo);

	return &pdo->comm;
}

const struct co_pdo_map_par *
co_tpdo_get_map_par(const co_tpdo_t *pdo)
{
	assert(pdo);

	return &pdo->map;
}

void
co_tpdo_get_ind(const co_tpdo_t *pdo, co_tpdo_ind_t **pind, void **pdata)
{
	assert(pdo);

	if (pind)
		*pind = pdo->ind;
	if (pdata)
		*pdata = pdo->data;
}

void
co_tpdo_set_ind(co_tpdo_t *pdo, co_tpdo_ind_t *ind, void *data)
{
	assert(pdo);

	pdo->ind = ind;
	pdo->data = data;
}

void
co_tpdo_get_sample_ind(
		const co_tpdo_t *pdo, co_tpdo_sample_ind_t **pind, void **pdata)
{
	assert(pdo);

	if (pind)
		*pind = pdo->sample_ind;
	if (pdata)
		*pdata = pdo->sample_data;
}

void
co_tpdo_set_sample_ind(co_tpdo_t *pdo, co_tpdo_sample_ind_t *ind, void *data)
{
	assert(pdo);

	pdo->sample_ind = ind ? ind : &default_sample_ind;
	pdo->sample_data = ind ? data : NULL;
}

int
co_tpdo_event(co_tpdo_t *pdo)
{
	assert(pdo);

	if (pdo->stopped)
		return 0;

	// Check whether the PDO exists and is valid.
	if (pdo->comm.cobid & CO_PDO_COBID_VALID)
		return 0;

	// See table 72 (Description of TPDO transmission type) in CiA 301.
	switch (pdo->comm.trans) {
	case 0x00: pdo->event = 1; break;
	case 0xfd:
		if (co_tpdo_init_frame(pdo, &pdo->msg) == -1)
			return -1;
		break;
	case 0xfe:
	case 0xff:
		if (pdo->comm.inhibit) {
			// Check whether the inhibit time has passed.
			struct timespec now;
			can_net_get_time(pdo->net, &now);
			if (timespec_cmp(&now, &pdo->inhibit) < 0) {
				set_errnum(ERRNUM_AGAIN);
				return -1;
			}
			pdo->inhibit = now;
		}

		// In case of an event-driven TPDO, send the frame right away.
		if (co_tpdo_init_frame(pdo, &pdo->msg) == -1)
			return -1;
		if (co_tpdo_send_frame(pdo, &pdo->msg) == -1)
			return -1;

		if (pdo->comm.inhibit) {
			// The inhibit time value is defined as a multiple of
			// 100 microseconds.
			timespec_add_usec(
					&pdo->inhibit, pdo->comm.inhibit * 100);
		}
		break;
	default:
		// Ignore events if the transmission type is synchronous.
		return 0;
	}

	co_tpdo_init_timer_event(pdo);

	return 0;
}

int
co_tpdo_sync(co_tpdo_t *pdo, co_unsigned8_t cnt)
{
	assert(pdo);

	if (cnt > 240) {
		set_errnum(ERRNUM_INVAL);
		return -1;
	}

	// Check whether the PDO exists and is valid.
	if (pdo->comm.cobid & CO_PDO_COBID_VALID)
		return 0;

	// Ignore SYNC objects if the transmission type is not synchronous.
	// See table 72 (Description of TPDO transmission type) in CiA 301.
	if (pdo->comm.trans > 0xf0 && pdo->comm.trans != 0xfc)
		return 0;

	// Wait for the SYNC counter to equal the SYNC start value.
	if (pdo->sync && cnt) {
		if (pdo->sync != cnt)
			return 0;
		pdo->sync = 0;
		pdo->cnt = 0;
	}

	// Reset the time window for synchronous PDOs.
	pdo->swnd = 0;
	co_tpdo_init_timer_swnd(pdo);

	if (!pdo->comm.trans) {
		// In case of a synchronous (acyclic) TPDO, do nothing unless an
		// event occurred.
		if (!pdo->event)
			return 0;
		pdo->event = 0;
	} else if (pdo->comm.trans <= 0xf0) {
		// In case of a synchronous (cyclic) TPDO, do nothing unless the
		// n-th SYNC object has been received.
		if (++pdo->cnt < pdo->comm.trans)
			return 0;
		pdo->cnt = 0;
	}

	assert(pdo->sample_ind);
	return pdo->sample_ind(pdo, pdo->sample_data);
}

int
co_tpdo_sample_res(co_tpdo_t *pdo, co_unsigned32_t ac)
{
	assert(pdo);

	// Check whether the PDO exists and is valid.
	if (pdo->comm.cobid & CO_PDO_COBID_VALID)
		return 0;

	// Ignore the sampling result if the transmission type is not
	// synchronous or RTR-only. See table 72 (Description of TPDO
	// transmission type) in CiA 301.
	if (pdo->comm.trans > 0xf0 && pdo->comm.trans != 0xfc
			&& pdo->comm.trans != 0xfd)
		return 0;

	// Check if the synchronous window expired.
	if (!ac && pdo->comm.trans != 0xfd && pdo->swnd)
		ac = CO_SDO_AC_TIMEOUT;

	// Do not send a PDO in case of an error.
	if (ac) {
		if (pdo->ind)
			pdo->ind(pdo, ac, NULL, 0, pdo->data);
		return 0;
	}

	if (co_tpdo_init_frame(pdo, &pdo->msg) == -1)
		return -1;

	// In case of an RTR-only (synchronous) PDO, wait for the RTR.
	if (pdo->comm.trans == 0xfc)
		return 0;

	return co_tpdo_send_frame(pdo, &pdo->msg);
}

void
co_tpdo_get_next(const co_tpdo_t *pdo, struct timespec *tp)
{
	assert(pdo);

	if (tp)
		*tp = pdo->inhibit;
}

static void
co_tpdo_init_recv(co_tpdo_t *pdo)
{
	assert(pdo);

	if (!(pdo->comm.cobid & CO_PDO_COBID_VALID)
			&& !(pdo->comm.cobid & CO_PDO_COBID_RTR)) {
		// Register the receiver under the specified CAN-ID.
		uint_least32_t id = pdo->comm.cobid;
		uint_least8_t flags = CAN_FLAG_RTR;
		if (id & CO_PDO_COBID_FRAME) {
			id &= CAN_MASK_EID;
			flags |= CAN_FLAG_IDE;
		} else {
			id &= CAN_MASK_BID;
		}
		can_recv_start(pdo->recv, pdo->net, id, flags);
	} else {
		// Stop the receiver unless the TPDO is valid and allows RTR.
		can_recv_stop(pdo->recv);
	}
}

static void
co_tpdo_init_timer_event(co_tpdo_t *pdo)
{
	assert(pdo);

	can_timer_stop(pdo->timer_event);
	if (!(pdo->comm.cobid & CO_PDO_COBID_VALID) && pdo->comm.trans >= 0xfe
			&& pdo->comm.event)
		// Reset the event timer.
		can_timer_timeout(pdo->timer_event, pdo->net, pdo->comm.event);
}

static void
co_tpdo_init_timer_swnd(co_tpdo_t *pdo)
{
	assert(pdo);
	assert(!(pdo->comm.cobid & CO_PDO_COBID_VALID));
	assert(pdo->comm.trans <= 0xf0 || pdo->comm.trans == 0xfc);

	can_timer_stop(pdo->timer_swnd);
	// Ignore the synchronous window length unless the TPDO is valid and
	// synchronous.
	co_unsigned32_t swnd = co_dev_get_val_u32(pdo->dev, 0x1007, 0x00);
	if (swnd) {
		struct timespec start = { 0, 0 };
		can_net_get_time(pdo->net, &start);
		timespec_add_usec(&start, swnd);
		can_timer_start(pdo->timer_swnd, pdo->net, &start, NULL);
	}
}

static co_unsigned32_t
co_1800_dn_ind(co_sub_t *sub, struct co_sdo_req *req, co_unsigned32_t ac,
		void *data)
{
	assert(sub);
	assert(req);
	co_tpdo_t *pdo = data;
	assert(pdo);
	assert(co_obj_get_idx(co_sub_get_obj(sub)) == 0x1800 + pdo->num - 1);

	co_unsigned16_t type = co_sub_get_type(sub);
	assert(!co_type_is_array(type));

	if (ac)
		return ac;

	union co_val val;
	if (co_sdo_req_dn_val(req, type, &val, &ac) == -1)
		return ac;

	switch (co_sub_get_subidx(sub)) {
	case 0: return CO_SDO_AC_NO_WRITE;
	case 1: {
		assert(type == CO_DEFTYPE_UNSIGNED32);
		co_unsigned32_t cobid = val.u32;
		co_unsigned32_t cobid_old = co_sub_get_val_u32(sub);
		if (cobid == cobid_old)
			return 0;

		// The CAN-ID cannot be changed when the PDO is and remains
		// valid.
		const bool valid = !(cobid & CO_PDO_COBID_VALID);
		const bool valid_old = !(cobid_old & CO_PDO_COBID_VALID);
		const uint_least32_t canid = cobid & CAN_MASK_EID;
		const uint_least32_t canid_old = cobid_old & CAN_MASK_EID;
		if (valid && valid_old && canid != canid_old)
			return CO_SDO_AC_PARAM_VAL;

		// A 29-bit CAN-ID is only valid if the frame bit is set.
		if (!(cobid & CO_PDO_COBID_FRAME)
				&& (cobid & (CAN_MASK_EID ^ CAN_MASK_BID)))
			return CO_SDO_AC_PARAM_VAL;

		pdo->comm.cobid = cobid;

		if (valid && !valid_old) {
			can_net_get_time(pdo->net, &pdo->inhibit);
			pdo->event = 0;
			pdo->sync = pdo->comm.sync;
			pdo->cnt = 0;
		}

		pdo->msg = (struct can_msg)CAN_MSG_INIT;
		pdo->event = 0;
		pdo->swnd = 1;

		co_tpdo_init_recv(pdo);
		co_tpdo_init_timer_event(pdo);
		can_timer_stop(pdo->timer_swnd);
		break;
	}
	case 2: {
		// See table 72 (Description of TPDO transmission type) in CiA
		// 301.
		assert(type == CO_DEFTYPE_UNSIGNED8);
		co_unsigned8_t trans = val.u8;
		co_unsigned8_t trans_old = co_sub_get_val_u8(sub);
		if (trans == trans_old)
			return 0;

		// Transmission types 0xF1..0xFB are reserved.
		if (trans > 0xf0 && trans < 0xfc)
			return CO_SDO_AC_PARAM_VAL;

		// Check whether RTR is allowed on this PDO.
		if ((trans == 0xfc || trans == 0xfd)
				&& (pdo->comm.cobid & CO_PDO_COBID_RTR))
			return CO_SDO_AC_PARAM_VAL;

		pdo->comm.trans = trans;

		co_tpdo_init_recv(pdo);
		break;
	}
	case 3: {
		assert(type == CO_DEFTYPE_UNSIGNED16);
		co_unsigned16_t inhibit = val.u16;
		co_unsigned16_t inhibit_old = co_sub_get_val_u16(sub);
		if (inhibit == inhibit_old)
			return 0;

		// The inhibit time cannot be changed while the PDO exists and
		// is valid.
		if (!(pdo->comm.cobid & CO_PDO_COBID_VALID))
			return CO_SDO_AC_PARAM_VAL;

		pdo->comm.inhibit = inhibit;
		break;
	}
	case 5: {
		assert(type == CO_DEFTYPE_UNSIGNED16);
		co_unsigned16_t event = val.u16;
		co_unsigned16_t event_old = co_sub_get_val_u16(sub);
		if (event == event_old)
			return 0;

		pdo->comm.event = event;

		co_tpdo_init_timer_event(pdo);
		break;
	}
	case 6: {
		assert(type == CO_DEFTYPE_UNSIGNED8);
		co_unsigned8_t sync = val.u8;
		co_unsigned8_t sync_old = co_sub_get_val_u8(sub);
		if (sync == sync_old)
			return 0;

		// The SYNC start value cannot be changed while the PDO exists
		// and is valid.
		if (!(pdo->comm.cobid & CO_PDO_COBID_VALID))
			return CO_SDO_AC_PARAM_VAL;

		pdo->comm.sync = sync;
		break;
	}
	default: return CO_SDO_AC_NO_SUB;
	}

	co_sub_dn(sub, &val);

	return 0;
}

static co_unsigned32_t
co_1a00_dn_ind(co_sub_t *sub, struct co_sdo_req *req, co_unsigned32_t ac,
		void *data)
{
	assert(sub);
	assert(req);
	co_tpdo_t *pdo = data;
	assert(pdo);
	assert(co_obj_get_idx(co_sub_get_obj(sub)) == 0x1a00 + pdo->num - 1);

	co_unsigned16_t type = co_sub_get_type(sub);
	assert(!co_type_is_array(type));

	if (ac)
		return ac;

	union co_val val;
	if (co_sdo_req_dn_val(req, type, &val, &ac) == -1)
		return ac;

	const bool valid = !(pdo->comm.cobid & CO_PDO_COBID_VALID);

	if (!co_sub_get_subidx(sub)) {
		assert(type == CO_DEFTYPE_UNSIGNED8);
		co_unsigned8_t n = val.u8;
		co_unsigned8_t n_old = co_sub_get_val_u8(sub);
		if (n == n_old)
			return 0;

		// The PDO mapping cannot be changed when the PDO is valid.
		if (valid || n > CO_PDO_NUM_MAPS)
			return CO_SDO_AC_PARAM_VAL;

		size_t bits = 0;
		for (size_t i = 1; i <= n; i++) {
			co_unsigned32_t map = pdo->map.map[i - 1];
			if (!map)
				continue;

			// See figure 73 (Structure of TPDO mapping) in CiA 301.
			co_unsigned16_t idx = (map >> 16) & 0xffff;
			co_unsigned8_t subidx = (map >> 8) & 0xff;
			co_unsigned8_t len = map & 0xff;

			// Check the PDO length (in bits).
			if ((bits += len) > CAN_MAX_LEN * 8)
				return CO_SDO_AC_PDO_LEN;

			// Check whether the sub-object exists and can be mapped
			// into a PDO.
			if ((ac = co_dev_chk_tpdo(pdo->dev, idx, subidx)))
				return ac;
		}

		pdo->map.n = n;
	} else {
		assert(type == CO_DEFTYPE_UNSIGNED32);
		co_unsigned32_t map = val.u32;
		co_unsigned32_t map_old = co_sub_get_val_u32(sub);
		if (map == map_old)
			return 0;

		// The PDO mapping cannot be changed when the PDO is valid or
		// sub-index 0x00 is non-zero.
		if (valid || pdo->map.n)
			return CO_SDO_AC_PARAM_VAL;

		if (map) {
			// See figure 73 (Structure of TPDO mapping) in CiA 301.
			co_unsigned16_t idx = (map >> 16) & 0xffff;
			co_unsigned8_t subidx = (map >> 8) & 0xff;
			// Check whether the sub-object exists and can be mapped
			// into a PDO.
			if ((ac = co_dev_chk_tpdo(pdo->dev, idx, subidx)))
				return ac;
		}

		pdo->map.map[co_sub_get_subidx(sub) - 1] = map;
	}

	co_sub_dn(sub, &val);

	return 0;
}

static int
co_tpdo_recv(const struct can_msg *msg, void *data)
{
	assert(msg);
	assert(msg->flags & CAN_FLAG_RTR);
	(void)msg;
	co_tpdo_t *pdo = data;
	assert(pdo);

	// See table 72 (Description of TPDO transmission type) in CiA 301.
	switch (pdo->comm.trans) {
	case 0xfc: {
		uint_least32_t mask = (pdo->comm.cobid & CO_PDO_COBID_FRAME)
				? CAN_MASK_EID
				: CAN_MASK_BID;
		// Ignore the RTR if no buffered CAN frame is available.
		if (pdo->msg.id != (pdo->comm.cobid & mask))
			break;
		co_tpdo_send_frame(pdo, &pdo->msg);
		break;
	}
	case 0xfd:
		// Start sampling.
		assert(pdo->sample_ind);
		pdo->sample_ind(pdo, pdo->sample_data);
		break;
	default: break;
	}

	return 0;
}

static int
co_tpdo_timer_event(const struct timespec *tp, void *data)
{
	(void)tp;
	co_tpdo_t *pdo = data;
	assert(pdo);

	int errsv = get_errc();
	if (co_tpdo_event(pdo) == -1) {
		// Restart the event timer, even if we failed to send a PDO.
		co_tpdo_init_timer_event(pdo);
		set_errc(errsv);
	}

	return 0;
}

static int
co_tpdo_timer_swnd(const struct timespec *tp, void *data)
{
	(void)tp;
	co_tpdo_t *pdo = data;
	assert(pdo);

	pdo->swnd = 1;

	return 0;
}

static int
default_sample_ind(co_tpdo_t *pdo, void *data)
{
	(void)data;

	return co_tpdo_sample_res(pdo, 0);
}

static int
co_tpdo_init_frame(co_tpdo_t *pdo, struct can_msg *msg)
{
	assert(pdo);
	assert(msg);

	*msg = (struct can_msg)CAN_MSG_INIT;
	msg->id = pdo->comm.cobid;
	if (pdo->comm.cobid & CO_PDO_COBID_FRAME) {
		msg->id &= CAN_MASK_EID;
		msg->flags |= CAN_FLAG_IDE;
	} else {
		msg->id &= CAN_MASK_BID;
	}

	size_t n = CAN_MAX_LEN;
	co_unsigned32_t ac = co_pdo_up(
			&pdo->map, pdo->dev, &pdo->req, msg->data, &n);
	if (ac) {
		if (pdo->ind)
			pdo->ind(pdo, ac, NULL, 0, pdo->data);
		return -1;
	}
	msg->len = n;

	return 0;
}

static int
co_tpdo_send_frame(co_tpdo_t *pdo, const struct can_msg *msg)
{
	int result = can_net_send(pdo->net, msg);
	if (pdo->ind) {
		if (!result) {
			pdo->ind(pdo, 0, pdo->msg.data, pdo->msg.len,
					pdo->data);
		} else {
			pdo->ind(pdo, CO_SDO_AC_ERROR, NULL, 0, pdo->data);
		}
	}
	return result;
}

#endif // !LELY_NO_CO_TPDO

static void *
co_tpdo_alloc(can_net_t *net)
{
	co_tpdo_t *pdo = mem_alloc(can_net_get_alloc(net), co_tpdo_alignof(),
			co_tpdo_sizeof());
	if (!pdo)
		return NULL;

	pdo->net = net;

	return pdo;
}

static void
co_tpdo_free(co_tpdo_t *pdo)
{
	mem_free(co_tpdo_get_alloc(pdo), pdo);
}

static co_tpdo_t *
co_tpdo_init(co_tpdo_t *pdo, can_net_t *net, co_dev_t *dev, co_unsigned16_t num)
{
	assert(pdo);
	assert(net);
	assert(dev);

	int errc = 0;

	if (!num || num > CO_NUM_PDOS) {
		errc = errnum2c(ERRNUM_INVAL);
		goto error_param;
	}

	// Find the PDO parameters in the object dictionary.
	const co_obj_t *const obj_1800 = co_dev_find_obj(dev, 0x1800 + num - 1);
	const co_obj_t *const obj_1a00 = co_dev_find_obj(dev, 0x1a00 + num - 1);
	if (!obj_1800 || !obj_1a00) {
		errc = errnum2c(ERRNUM_INVAL);
		goto error_param;
	}

	pdo->net = net;
	pdo->dev = dev;
	pdo->num = num;

	pdo->stopped = true;

	memset(&pdo->comm, 0, sizeof(pdo->comm));
	memset(&pdo->map, 0, sizeof(pdo->map));

	pdo->recv = can_recv_create(co_tpdo_get_alloc(pdo));
	if (!pdo->recv) {
		errc = get_errc();
		goto error_create_recv;
	}
	can_recv_set_func(pdo->recv, &co_tpdo_recv, pdo);

	pdo->timer_event = can_timer_create(co_tpdo_get_alloc(pdo));
	if (!pdo->timer_event) {
		errc = get_errc();
		goto error_create_timer_event;
	}
	can_timer_set_func(pdo->timer_event, &co_tpdo_timer_event, pdo);

	pdo->timer_swnd = can_timer_create(co_tpdo_get_alloc(pdo));
	if (!pdo->timer_swnd) {
		errc = get_errc();
		goto error_create_timer_swnd;
	}
	can_timer_set_func(pdo->timer_swnd, &co_tpdo_timer_swnd, pdo);

	pdo->msg = (struct can_msg)CAN_MSG_INIT;

	pdo->inhibit = (struct timespec){ 0, 0 };
	pdo->event = 0;
	pdo->swnd = 1;
	pdo->sync = 0;
	pdo->cnt = 0;

	co_sdo_req_init(&pdo->req, NULL);

	pdo->ind = NULL;
	pdo->data = NULL;

	pdo->sample_ind = &default_sample_ind;
	pdo->sample_data = NULL;

	return pdo;

	// can_timer_destroy(pdo->timer_swnd);
error_create_timer_swnd:
	can_timer_destroy(pdo->timer_event);
error_create_timer_event:
	can_recv_destroy(pdo->recv);
error_create_recv:
error_param:
	set_errc(errc);
	return NULL;
}

static void
co_tpdo_fini(co_tpdo_t *pdo)
{
	assert(pdo);
	assert(pdo->num >= 1 && pdo->num <= CO_NUM_PDOS);

	co_tpdo_stop(pdo);

	co_sdo_req_fini(&pdo->req);

	can_timer_destroy(pdo->timer_swnd);
	can_timer_destroy(pdo->timer_event);
	can_recv_destroy(pdo->recv);
}
