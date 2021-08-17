/**@file
 * This file is part of the CAN library; it contains the implementation of the
 * CAN network interface.
 *
 * @see lely/can/net.h
 *
 * @copyright 2015-2021 Lely Industries N.V.
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

#include "can.h"
#include <lely/can/net.h>
#include <lely/util/cmp.h>
#include <lely/util/dllist.h>
#include <lely/util/error.h>
#include <lely/util/pheap.h>
#include <lely/util/rbtree.h>
#include <lely/util/time.h>

#include <assert.h>

/// A CAN network interface.
struct can_net {
	/// A pointer to the memory allocator used to allocate this struct.
	alloc_t *alloc;
	/// The heap containing all timers.
	struct pheap timer_heap;
	/// The current time.
	struct timespec time;
	/// The time at which the next timer triggers.
	struct timespec next;
	/// A pointer to the callback function invoked by can_net_set_next().
	can_timer_func_t *next_func;
	/// A pointer to user-specified data for #next_func.
	void *next_data;
	/// The tree containing all receivers.
	struct rbtree recv_tree;
	/// A pointer to the callback function invoked by can_net_send().
	can_send_func_t *send_func;
	/// A pointer to the user-specified data for #send_func.
	void *send_data;
	/// The active CAN bus identifier.
	uint_least8_t active_bus;
};

/**
 * Invokes the callback function if the time at which the next CAN timer
 * triggers has been updated.
 */
static void can_net_set_next(can_net_t *net);

/// Allocates the #can_net_t structure using the provided allocator.
static can_net_t *can_net_alloc(alloc_t *alloc);

/// Frees the #can_net_t structure using the allocator provided to
/// can_net_alloc().
static void can_net_free(can_net_t *net);

/// Initializes the #can_net_t structure.
static void can_net_init(can_net_t *net, uint_least8_t bus_id);

/// Finalizes the #can_net_t structure.
static void can_net_fini(can_net_t *net);

/// A CAN timer.
struct can_timer {
	/// A pointer to the memory allocator used to allocate this struct.
	alloc_t *alloc;
	/// The node of this timer in the tree of timers.
	struct pnode node;
	/**
	 * A pointer to the network interface with which this timer is
	 * registered.
	 */
	can_net_t *net;
	/// The time at which the timer should trigger.
	struct timespec start;
	/// The interval between successive triggers.
	struct timespec interval;
	/// A pointer to the callback function invoked by can_net_set_time().
	can_timer_func_t *func;
	/// A pointer to the user-specified data for #func.
	void *data;
};

/// Allocates the #can_timer_t using the provided allocator.
static can_timer_t *can_timer_alloc(alloc_t *alloc);

/// Frees the #can_timer_t structure using the allocator provided to
/// can_timer_alloc().
static void can_timer_free(can_timer_t *timer);

/// Initializes the #can_timer_t structure.
static void can_timer_init(can_timer_t *timer);

/// Finalizes the #can_timer_t structure.
static void can_timer_fini(can_timer_t *timer);

/**
 * The type of the key used to match CAN frame receivers to CAN frames. The key
 * is a combination of the CAN identifier and the flags.
 */
#if LELY_NO_CANFD
typedef uint_least32_t can_recv_key_t;
#else
typedef uint_least64_t can_recv_key_t;
#endif

/// A CAN frame receiver.
struct can_recv {
	/// A pointer to the memory allocator used to allocate this struct.
	alloc_t *alloc;
	/// The node of this receiver in the tree of receivers.
	struct rbnode node;
	/// The list of CAN frame receivers with the same key.
	struct dlnode list;
	/**
	 * A pointer to the network interface with which this receiver is
	 * registered.
	 */
	can_net_t *net;
	/// The key used in #node.
	can_recv_key_t key;
	/// A pointer to the callback function invoked by can_net_recv().
	can_recv_func_t *func;
	/// A pointer to the user-specified data for #func.
	void *data;
};

/// Computes a CAN receiver key from a CAN identifier and flags.
static inline can_recv_key_t can_recv_key(
		uint_least32_t id, uint_least8_t flags);

/// The function used to compare to CAN receiver keys.
static int can_recv_key_cmp(const void *p1, const void *p2);

/// Allocates the #can_recv_t structure using the provided allocator.
static can_recv_t *can_recv_alloc(alloc_t *alloc);

/// Frees the #can_recv_t structure using the allocator provided to
/// can_recv_alloc().
static void can_recv_free(can_recv_t *recv);

/// Initializes the #can_recv_t structure.
static void can_recv_init(can_recv_t *recv);

/// Finalizes the #can_recv_t structure.
static void can_recv_fini(can_recv_t *recv);

size_t
can_net_alignof(void)
{
	return _Alignof(can_net_t);
}

size_t
can_net_sizeof(void)
{
	return sizeof(can_net_t);
}

can_net_t *
can_net_create(alloc_t *alloc, const uint_least8_t bus_id)
{
	can_net_t *net = can_net_alloc(alloc);
	if (!net)
		return NULL;

	can_net_init(net, bus_id);

	return net;
}

void
can_net_destroy(can_net_t *net)
{
	if (net) {
		can_net_fini(net);
		can_net_free(net);
	}
}

alloc_t *
can_net_get_alloc(const can_net_t *net)
{
	assert(net);

	return net->alloc;
}

void
can_net_get_time(const can_net_t *net, struct timespec *tp)
{
	assert(net);

	if (tp)
		*tp = net->time;
}

int
can_net_set_time(can_net_t *net, const struct timespec *tp)
{
	assert(net);
	assert(tp);

	net->time = *tp;

	int errc = get_errc();
	int result = 0;

	// Keep processing the first timer until we're done.
	struct pnode *node;
	while ((node = pheap_first(&net->timer_heap)) != NULL) {
		can_timer_t *timer = structof(node, can_timer_t, node);
		// If the timeout of the first timer is after the current time,
		// we're done.
		if (timespec_cmp(&timer->start, &net->time) > 0)
			break;

		// Requeue the timer before invoking the callback function.
		pheap_remove(&net->timer_heap, &timer->node);
		timer->net = NULL;
		if (timer->interval.tv_sec || timer->interval.tv_nsec) {
			timespec_add(&timer->start, &timer->interval);
			timer->net = net;
			pheap_insert(&net->timer_heap, &timer->node);
		}

		// Invoke the callback function and check the result.
		if (timer->func && timer->func(&net->time, timer->data)
				&& !result) {
			// Store the first error that occurs.
			errc = get_errc();
			result = -1;
		}
	}

	can_net_set_next(net);

	set_errc(errc);
	return result;
}

void
can_net_get_next_func(
		const can_net_t *net, can_timer_func_t **pfunc, void **pdata)
{
	assert(net);

	if (pfunc)
		*pfunc = net->next_func;
	if (pdata)
		*pdata = net->next_data;
}

void
can_net_set_next_func(can_net_t *net, can_timer_func_t *func, void *data)
{
	assert(net);

	net->next_func = func;
	net->next_data = data;
}

ssize_t
can_net_recv(can_net_t *net, const struct can_msg *msg,
		const uint_least8_t bus_id)
{
	assert(net);
	assert(msg);

	if (bus_id != net->active_bus)
		return 0;

	int errc = get_errc();
	ssize_t result = 1;

	can_recv_key_t key = can_recv_key(msg->id, msg->flags);
	struct rbnode *node = rbtree_find(&net->recv_tree, &key);
	if (node) {
		// Loop over all matching receivers.
		can_recv_t *recv = structof(node, can_recv_t, node);
		dlnode_foreach (&recv->list, node) { // LCOV_EXCL_BR_LINE
			recv = structof(node, can_recv_t, list);
			// Invoke the callback function and check the result.
			if (recv->func && recv->func(msg, recv->data)
					&& (result != -1)) {
				// Store the first error that occurs.
				errc = get_errc();
				result = -1;
			}
		}
	}

	set_errc(errc);
	return result;
}

int
can_net_send(can_net_t *net, const struct can_msg *msg)
{
	assert(net);
	assert(msg);

	if (!net->send_func) {
		set_errnum(ERRNUM_NOSYS);
		return -1;
	}

	return net->send_func(msg, net->active_bus, net->send_data);
}

void
can_net_get_send_func(
		const can_net_t *net, can_send_func_t **pfunc, void **pdata)
{
	assert(net);

	if (pfunc)
		*pfunc = net->send_func;
	if (pdata)
		*pdata = net->send_data;
}

void
can_net_set_send_func(can_net_t *net, can_send_func_t *func, void *data)
{
	assert(net);

	net->send_func = func;
	net->send_data = data;
}

uint_least8_t
can_net_get_active_bus(const can_net_t *net)
{
	return net->active_bus;
}

void
can_net_set_active_bus(can_net_t *net, const uint_least8_t bus_id)
{
	net->active_bus = bus_id;
}

size_t
can_timer_alignof(void)
{
	return _Alignof(can_timer_t);
}

size_t
can_timer_sizeof(void)
{
	return sizeof(can_timer_t);
}

can_timer_t *
can_timer_create(alloc_t *alloc)
{
	can_timer_t *timer = can_timer_alloc(alloc);
	if (!timer)
		return NULL;

	can_timer_init(timer);

	return timer;
}

void
can_timer_destroy(can_timer_t *timer)
{
	if (timer) {
		can_timer_fini(timer);
		can_timer_free(timer);
	}
}

alloc_t *
can_timer_get_alloc(const can_timer_t *timer)
{
	assert(timer);

	return timer->alloc;
}

void
can_timer_get_func(const can_timer_t *timer, can_timer_func_t **pfunc,
		void **pdata)
{
	assert(timer);

	if (pfunc)
		*pfunc = timer->func;
	if (pdata)
		*pdata = timer->data;
}

void
can_timer_set_func(can_timer_t *timer, can_timer_func_t *func, void *data)
{
	assert(timer);

	timer->func = func;
	timer->data = data;
}

void
can_timer_start(can_timer_t *timer, can_net_t *net,
		const struct timespec *start, const struct timespec *interval)
{
	assert(timer);
	assert(net);

	can_timer_stop(timer);

	if (!start && !interval)
		return;

	if (interval)
		timer->interval = *interval;
	else
		timer->interval = (struct timespec){ 0, 0 };

	if (start) {
		timer->start = *start;
	} else {
		can_net_get_time(net, &timer->start);
		timespec_add(&timer->start, &timer->interval);
	}

	timer->net = net;

	pheap_insert(&timer->net->timer_heap, &timer->node);

	can_net_set_next(net);
}

void
can_timer_stop(can_timer_t *timer)
{
	assert(timer);

	can_net_t *net = timer->net;
	if (!net)
		return;

	pheap_remove(&timer->net->timer_heap, &timer->node);

	timer->net = NULL;

	can_net_set_next(net);
}

void
can_timer_timeout(can_timer_t *timer, can_net_t *net, int_least32_t timeout)
{
	if (timeout < 0) {
		can_timer_stop(timer);
	} else {
		struct timespec start = { 0, 0 };
		can_net_get_time(net, &start);
		timespec_add_msec(&start, timeout);

		can_timer_start(timer, net, &start, NULL);
	}
}

size_t
can_recv_alignof(void)
{
	return _Alignof(can_recv_t);
}

size_t
can_recv_sizeof(void)
{
	return sizeof(can_recv_t);
}

can_recv_t *
can_recv_create(alloc_t *alloc)
{
	can_recv_t *recv = can_recv_alloc(alloc);
	if (!recv)
		return NULL;

	can_recv_init(recv);

	return recv;
}

void
can_recv_destroy(can_recv_t *recv)
{
	if (recv) {
		can_recv_fini(recv);
		can_recv_free(recv);
	}
}

alloc_t *
can_recv_get_alloc(const can_recv_t *recv)
{
	assert(recv);

	return recv->alloc;
}

void
can_recv_get_func(const can_recv_t *recv, can_recv_func_t **pfunc, void **pdata)
{
	assert(recv);

	if (pfunc)
		*pfunc = recv->func;
	if (pdata)
		*pdata = recv->data;
}

void
can_recv_set_func(can_recv_t *recv, can_recv_func_t *func, void *data)
{
	assert(recv);

	recv->func = func;
	recv->data = data;
}

void
can_recv_start(can_recv_t *recv, can_net_t *net, uint_least32_t id,
		uint_least8_t flags)
{
	assert(recv);
	assert(net);

	can_recv_stop(recv);

	recv->net = net;

	recv->key = can_recv_key(id, flags);
	struct rbnode *node = rbtree_find(&recv->net->recv_tree, &recv->key);
	if (node) {
		can_recv_t *prev = structof(node, can_recv_t, node);
		dlnode_insert_after(&prev->list, &recv->list);
	} else {
		rbtree_insert(&recv->net->recv_tree, &recv->node);
		dlnode_init(&recv->list);
	}
}

void
can_recv_stop(can_recv_t *recv)
{
	assert(recv);

	if (!recv->net)
		return;

	struct dlnode *prev = recv->list.prev;
	struct dlnode *next = recv->list.next;

	if (!prev)
		rbtree_remove(&recv->net->recv_tree, &recv->node);
	dlnode_remove(&recv->list);
	dlnode_init(&recv->list);

	recv->net = NULL;

	if (!prev && next) {
		recv = structof(next, can_recv_t, list);
		rbtree_insert(&recv->net->recv_tree, &recv->node);
	}
}

static void
can_net_set_next(can_net_t *net)
{
	assert(net);

	const struct pnode *const node = pheap_first(&net->timer_heap);
	if (!node)
		return;
	const can_timer_t *const timer = structof(node, can_timer_t, node);

	net->next = timer->start;
	if (net->next_func)
		net->next_func(&net->next, net->next_data);
}

static inline can_recv_key_t
can_recv_key(uint_least32_t id, uint_least8_t flags)
{
	id &= (flags & CAN_FLAG_IDE) ? CAN_MASK_EID : CAN_MASK_BID;
	return (can_recv_key_t)id | ((can_recv_key_t)flags << 29);
}

static int
can_recv_key_cmp(const void *p1, const void *p2)
{
#if LELY_NO_CANFD
	return uint32_cmp(p1, p2);
#else
	return uint64_cmp(p1, p2);
#endif
}

static can_net_t *
can_net_alloc(alloc_t *alloc)
{
	can_net_t *net = mem_alloc(alloc, can_net_alignof(), can_net_sizeof());
	if (!net)
		return NULL;

	net->alloc = alloc;

	return net;
}

static void
can_net_free(can_net_t *net)
{
	assert(net);
	mem_free(net->alloc, net);
}

static void
can_net_init(can_net_t *net, const uint_least8_t bus_id)
{
	assert(net);

	pheap_init(&net->timer_heap, &timespec_cmp);

	net->time = (struct timespec){ 0, 0 };
	net->next = (struct timespec){ 0, 0 };

	net->next_func = NULL;
	net->next_data = NULL;

	rbtree_init(&net->recv_tree, &can_recv_key_cmp);

	net->send_func = NULL;
	net->send_data = NULL;

	net->active_bus = bus_id;
}

static void
can_net_fini(can_net_t *net)
{
	assert(net);

	rbtree_foreach (&net->recv_tree, node) {
		can_recv_t *recv = structof(node, can_recv_t, node);
		dlnode_foreach (&recv->list, node) // LCOV_EXCL_BR_LINE
			can_recv_stop(structof(node, can_recv_t, list));
	}

	struct pnode *node;
	while ((node = pheap_first(&net->timer_heap)) != NULL)
		can_timer_stop(structof(node, can_timer_t, node));
}

static can_timer_t *
can_timer_alloc(alloc_t *alloc)
{
	can_timer_t *timer = mem_alloc(
			alloc, can_timer_alignof(), can_timer_sizeof());
	if (!timer)
		return NULL;

	timer->alloc = alloc;

	return timer;
}

static void
can_timer_free(can_timer_t *timer)
{
	mem_free(timer->alloc, timer);
}

static void
can_timer_init(can_timer_t *timer)
{
	assert(timer);

	timer->node.key = &timer->start;

	timer->net = NULL;

	timer->start = (struct timespec){ 0, 0 };
	timer->interval = (struct timespec){ 0, 0 };

	timer->func = NULL;
	timer->data = NULL;
}

static void
can_timer_fini(can_timer_t *timer)
{
	can_timer_stop(timer);
}

static can_recv_t *
can_recv_alloc(alloc_t *alloc)
{
	can_recv_t *recv =
			mem_alloc(alloc, can_recv_alignof(), can_recv_sizeof());
	if (!recv)
		return NULL;

	recv->alloc = alloc;

	return recv;
}

static void
can_recv_free(can_recv_t *recv)
{
	mem_free(recv->alloc, recv);
}

static void
can_recv_init(can_recv_t *recv)
{
	assert(recv);

	rbnode_init(&recv->node, &recv->key);
	dlnode_init(&recv->list);

	recv->net = NULL;

	recv->key = 0;

	recv->func = NULL;
	recv->data = NULL;
}

static void
can_recv_fini(can_recv_t *recv)
{
	can_recv_stop(recv);
}
