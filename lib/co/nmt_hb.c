/**@file
 * This file is part of the CANopen library; it contains the implementation of
 * the NMT heartbeat consumer functions.
 *
 * @see lib/co/nmt_hb.h
 *
 * @copyright 2016-2020 Lely Industries N.V.
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

#include "nmt_hb.h"
#include "co.h"
#include <lely/co/dev.h>
#include <lely/util/diag.h>

#include <assert.h>

/// A CANopen NMT heartbeat consumer.
struct co_nmt_hb {
	/// A pointer to a CAN network interface.
	can_net_t *net;
	/// A pointer to an NMT master/slave service.
	co_nmt_t *nmt;
	/// A pointer to the CAN frame receiver.
	can_recv_t *recv;
	/// A pointer to the CAN timer.
	can_timer_t *timer;
	/// The node-ID.
	co_unsigned8_t id;
	/// The state of the node (excluding the toggle bit).
	co_unsigned8_t st;
	/// The consumer heartbeat time (in milliseconds).
	co_unsigned16_t ms;
	/// Indicates whether a heartbeat error occurred.
	co_nmt_ec_state_t state;
};

/// Allocates memory for #co_nmt_hb_t object using allocator from #can_net_t.
static void *co_nmt_hb_alloc(can_net_t *net);

/// Frees memory allocated for #co_nmt_hb_t object.
static void co_nmt_hb_free(co_nmt_hb_t *hb);

/// Initializes #co_nmt_hb_t object.
static co_nmt_hb_t *co_nmt_hb_init(
		co_nmt_hb_t *hb, can_net_t *net, co_nmt_t *nmt);

/// Finalizes #co_nmt_hb_t object.
static void co_nmt_hb_fini(co_nmt_hb_t *hb);

/**
 * The CAN receive callback function for a heartbeat consumer.
 *
 * @see can_recv_func_t
 */
static int co_nmt_hb_recv(const struct can_msg *msg, void *data);

/**
 * The CAN timer callback function for a heartbeat consumer.
 *
 * @see can_timer_func_t
 */
static int co_nmt_hb_timer(const struct timespec *tp, void *data);

size_t
co_nmt_hb_alignof(void)
{
	return _Alignof(co_nmt_hb_t);
}

size_t
co_nmt_hb_sizeof(void)
{
	return sizeof(co_nmt_hb_t);
}

co_nmt_hb_t *
co_nmt_hb_create(can_net_t *net, co_nmt_t *nmt)
{
	int errc = 0;

	co_nmt_hb_t *hb = co_nmt_hb_alloc(net);
	if (!hb) {
		errc = get_errc();
		goto error_alloc_hb;
	}

	if (!co_nmt_hb_init(hb, net, nmt)) {
		errc = get_errc();
		goto error_init_hb;
	}

	return hb;

error_init_hb:
	co_nmt_hb_free(hb);
error_alloc_hb:
	set_errc(errc);
	return NULL;
}

void
co_nmt_hb_destroy(co_nmt_hb_t *hb)
{
	if (hb) {
		co_nmt_hb_fini(hb);
		co_nmt_hb_free(hb);
	}
}

alloc_t *
co_nmt_hb_get_alloc(const co_nmt_hb_t *hb)
{
	assert(hb);

	return can_net_get_alloc(hb->net);
}

void
co_nmt_hb_set_1016(co_nmt_hb_t *hb, co_unsigned8_t id, co_unsigned16_t ms)
{
	assert(hb);

	can_recv_stop(hb->recv);
	can_timer_stop(hb->timer);

	hb->id = id;
	hb->st = 0;
	hb->ms = ms;
	hb->state = CO_NMT_EC_RESOLVED;

	if (hb->id && hb->id <= CO_NUM_NODES && hb->ms) {
		can_recv_start(hb->recv, hb->net, CO_NMT_EC_CANID(hb->id), 0);
	}
}

void
co_nmt_hb_set_st(co_nmt_hb_t *hb, co_unsigned8_t st)
{
	assert(hb);

	if (hb->id && hb->id <= CO_NUM_NODES && hb->ms) {
		hb->st = st;
		hb->state = CO_NMT_EC_RESOLVED;
		// Reset the CAN timer for the heartbeat consumer.
		can_timer_timeout(hb->timer, hb->net, hb->ms);
	}
}

static int
co_nmt_hb_recv(const struct can_msg *msg, void *data)
{
	assert(msg);
	co_nmt_hb_t *hb = data;
	assert(hb);
	assert(hb->id && hb->id <= CO_NUM_NODES);
	assert(msg->id == (uint_least32_t)CO_NMT_EC_CANID(hb->id));

	// Obtain the node status from the CAN frame. Ignore if the toggle bit
	// is set, since then it is not a heartbeat message.
	if (msg->len < 1)
		return 0;
	co_unsigned8_t st = msg->data[0];
	if (st & CO_NMT_ST_TOGGLE)
		return 0;

#if LELY_NO_CO_NMT_BOOT
	assert(hb->ms);
#else
	// This might happen upon receipt of a boot-up message. The 'boot slave'
	// process has disabled the heartbeat consumer, but the event has
	// already been scheduled.
	if (!hb->ms)
		return 0;
#endif

	// Update the state.
	co_unsigned8_t old_st = hb->st;
	co_nmt_ec_state_t old_state = hb->state;
	co_nmt_hb_set_st(hb, st);

	if (old_state == CO_NMT_EC_OCCURRED) {
		diag(DIAG_INFO, 0,
				"NMT: heartbeat time out resolved for node %d",
				hb->id);
		// If a heartbeat timeout event occurred, notify the user that
		// it has been resolved.
		co_nmt_hb_ind(hb->nmt, hb->id, hb->state, CO_NMT_EC_TIMEOUT, 0);
	}

	// Notify the application of the occurrence of a state change.
	if (st != old_st) {
		diag(DIAG_INFO, 0,
				"NMT: heartbeat state change occurred for node %d",
				hb->id);
		co_nmt_hb_ind(hb->nmt, hb->id, CO_NMT_EC_OCCURRED,
				CO_NMT_EC_STATE, st);
	}

	return 0;
}

static int
co_nmt_hb_timer(const struct timespec *tp, void *data)
{
	(void)tp;
	co_nmt_hb_t *hb = data;
	assert(hb);

	// Notify the application of the occurrence of a heartbeat timeout
	// event.
	diag(DIAG_INFO, 0, "NMT: heartbeat time out occurred for node %d",
			hb->id);
	hb->state = CO_NMT_EC_OCCURRED;
	co_nmt_hb_ind(hb->nmt, hb->id, hb->state, CO_NMT_EC_TIMEOUT, 0);

	return 0;
}

static void *
co_nmt_hb_alloc(can_net_t *net)
{
	co_nmt_hb_t *hb = mem_alloc(can_net_get_alloc(net), co_nmt_hb_alignof(),
			co_nmt_hb_sizeof());
	if (!hb)
		return NULL;

	hb->net = net;

	return hb;
}

static void
co_nmt_hb_free(co_nmt_hb_t *hb)
{
	mem_free(co_nmt_hb_get_alloc(hb), hb);
}

static co_nmt_hb_t *
co_nmt_hb_init(co_nmt_hb_t *hb, can_net_t *net, co_nmt_t *nmt)
{
	assert(hb);
	assert(net);
	assert(nmt);

	int errc = 0;

	hb->net = net;
	hb->nmt = nmt;

	hb->recv = can_recv_create(co_nmt_hb_get_alloc(hb));
	if (!hb->recv) {
		errc = get_errc();
		goto error_create_recv;
	}
	can_recv_set_func(hb->recv, &co_nmt_hb_recv, hb);

	hb->timer = can_timer_create(co_nmt_hb_get_alloc(hb));
	if (!hb->timer) {
		errc = get_errc();
		goto error_create_timer;
	}
	can_timer_set_func(hb->timer, &co_nmt_hb_timer, hb);

	hb->id = 0;
	hb->st = 0;
	hb->ms = 0;
	hb->state = CO_NMT_EC_RESOLVED;

	return hb;

	// can_timer_destroy(hb->timer);
error_create_timer:
	can_recv_destroy(hb->recv);
error_create_recv:
	set_errc(errc);
	return NULL;
}

static void
co_nmt_hb_fini(co_nmt_hb_t *hb)
{
	assert(hb);

	can_timer_destroy(hb->timer);
	can_recv_destroy(hb->recv);
}
