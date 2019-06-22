/**@file
 * This file is part of the I/O library; it contains the system serial port
 * implementation for POSIX platforms.
 *
 * @see lely/io2/sys/serial.h
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

#if _POSIX_C_SOURCE >= 200112L

#include "../stream.h"
#include "fd.h"
#include <lely/io2/ctx.h>
#include <lely/io2/posix/poll.h>
#include <lely/io2/sys/serial.h>
#include <lely/util/util.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>

#include <fcntl.h>
#include <poll.h>
#if !LELY_NO_THREADS
#include <pthread.h>
#include <sched.h>
#endif
#include <termios.h>
#include <unistd.h>

static io_ctx_t *io_serial_impl_dev_get_ctx(const io_dev_t *dev);
static ev_exec_t *io_serial_impl_dev_get_exec(const io_dev_t *dev);
static size_t io_serial_impl_dev_cancel(io_dev_t *dev, struct ev_task *task);
static size_t io_serial_impl_dev_abort(io_dev_t *dev, struct ev_task *task);

// clang-format off
static const struct io_dev_vtbl io_serial_impl_dev_vtbl = {
	&io_serial_impl_dev_get_ctx,
	&io_serial_impl_dev_get_exec,
	&io_serial_impl_dev_cancel,
	&io_serial_impl_dev_abort
};
// clang-format on

static io_dev_t *io_serial_impl_stream_get_dev(const io_stream_t *stream);
static ssize_t io_serial_impl_stream_readv(
		io_stream_t *stream, const struct io_buf *buf, int bufcnt);
static void io_serial_impl_stream_submit_readv(
		io_stream_t *stream, struct io_stream_readv *readv);
static ssize_t io_serial_impl_stream_writev(
		io_stream_t *stream, const struct io_buf *buf, int bufcnt);
static void io_serial_impl_stream_submit_writev(
		io_stream_t *stream, struct io_stream_writev *writev);

// clang-format off
static const struct io_stream_vtbl io_serial_impl_stream_vtbl = {
	&io_serial_impl_stream_get_dev,
	&io_serial_impl_stream_readv,
	&io_serial_impl_stream_submit_readv,
	&io_serial_impl_stream_writev,
	&io_serial_impl_stream_submit_writev
};
// clang-format on

static io_stream_t *io_serial_impl_get_stream(const io_serial_t *serial);
static int io_serial_impl_send_break(io_serial_t *serial);
static int io_serial_impl_flush(io_serial_t *serial);
static int io_serial_impl_purge(io_serial_t *serial, int how);
static int io_serial_impl_get_baud_rate(const io_serial_t *serial);
static int io_serial_impl_set_baud_rate(io_serial_t *serial, int optval);
static int io_serial_impl_get_flow_ctrl(const io_serial_t *serial);
static int io_serial_impl_set_flow_ctrl(io_serial_t *serial, int optval);
static int io_serial_impl_get_parity(const io_serial_t *serial);
static int io_serial_impl_set_parity(io_serial_t *serial, int optval);
static int io_serial_impl_get_stop_bits(const io_serial_t *serial);
static int io_serial_impl_set_stop_bits(io_serial_t *serial, int optval);
static int io_serial_impl_get_char_size(const io_serial_t *serial);
static int io_serial_impl_set_char_size(io_serial_t *serial, int optval);
static int io_serial_impl_get_rx_timeout(const io_serial_t *serial);
static int io_serial_impl_set_rx_timeout(io_serial_t *serial, int optval);
static int io_serial_impl_get_tx_timeout(const io_serial_t *serial);
static int io_serial_impl_set_tx_timeout(io_serial_t *serial, int optval);

// clang-format off
static const struct io_serial_vtbl io_serial_impl_vtbl = {
	io_serial_impl_get_stream,
	io_serial_impl_send_break,
	io_serial_impl_flush,
	io_serial_impl_purge,
	io_serial_impl_get_baud_rate,
	io_serial_impl_set_baud_rate,
	io_serial_impl_get_flow_ctrl,
	io_serial_impl_set_flow_ctrl,
	io_serial_impl_get_parity,
	io_serial_impl_set_parity,
	io_serial_impl_get_stop_bits,
	io_serial_impl_set_stop_bits,
	io_serial_impl_get_char_size,
	io_serial_impl_set_char_size,
	io_serial_impl_get_rx_timeout,
	io_serial_impl_set_rx_timeout,
	io_serial_impl_get_tx_timeout,
	io_serial_impl_set_tx_timeout
};
// clang-format on

static void io_serial_impl_svc_shutdown(struct io_svc *svc);

// clang-format off
static const struct io_svc_vtbl io_serial_impl_svc_vtbl = {
	NULL,
	&io_serial_impl_svc_shutdown
};
// clang-format on

/// The implementation of a serial port.
struct io_serial_impl {
	/// A pointer to the virtual table for the I/O device interface.
	const struct io_dev_vtbl *dev_vptr;
	/// A pointer to the virtual table for the I/O stream interface.
	const struct io_stream_vtbl *stream_vptr;
	/// A pointer to the virtual table for the serial port interface.
	const struct io_serial_vtbl *serial_vptr;
	/**
	 * A pointer to the polling instance used to watch for I/O events. If
	 * <b>poll</b> is NULL, operations are performed in blocking mode and
	 * the executor is used as a worker thread.
	 */
	io_poll_t *poll;
	/// The I/O service representing the serial port.
	struct io_svc svc;
	/**
	 * A pointer to the I/O context with which the serial port is
	 * registered.
	 */
	io_ctx_t *ctx;
	/// A pointer to the executor used to execute all I/O tasks.
	ev_exec_t *exec;
	/// The object used to monitor the file descriptor for I/O events.
	struct io_poll_watch watch;
	/// The task responsible for intiating read operations.
	struct ev_task readv_task;
	/// The task responsible for intiating write operations.
	struct ev_task writev_task;
#if !LELY_NO_THREADS
	/**
	 * The mutex protecting the file descriptor and the queues of pending
	 * operations.
	 */
	pthread_mutex_t mtx;
#endif
	/// The file descriptor.
	int fd;
	/// The attributes associated with #fd.
	struct termios ios;
	/// The timeout (in milliseconds) for read operations.
	int rx_timeout;
	/// The timeout (in milliseconds) for write operations.
	int tx_timeout;
	/// A flag indicating whether the I/O service has been shut down.
	unsigned shutdown : 1;
	/// A flag indicating whether #readv_task has been posted to #exec.
	unsigned readv_posted : 1;
	/// A flag indicating whether #writev_task has been posted to #exec.
	unsigned writev_posted : 1;
	/// The queue containing pending read operations.
	struct sllist readv_queue;
	/// The read operation currently being executed.
	struct ev_task *current_readv;
	/// The queue containing pending write operations.
	struct sllist writev_queue;
	/// The write operation currently being executed.
	struct ev_task *current_writev;
};

static void io_serial_impl_watch_func(struct io_poll_watch *watch, int events);
static void io_serial_impl_readv_task_func(struct ev_task *task);
static void io_serial_impl_writev_task_func(struct ev_task *task);

static inline struct io_serial_impl *io_serial_impl_from_dev(
		const io_dev_t *dev);
static inline struct io_serial_impl *io_serial_impl_from_stream(
		const io_stream_t *stream);
static inline struct io_serial_impl *io_serial_impl_from_serial(
		const io_serial_t *serial);
static inline struct io_serial_impl *io_serial_impl_from_svc(
		const struct io_svc *svc);

static void io_serial_impl_do_pop(struct io_serial_impl *impl,
		struct sllist *readv_queue, struct sllist *writev_queue,
		struct ev_task *task);

static size_t io_serial_impl_do_abort_tasks(struct io_serial_impl *impl);

static int io_serial_impl_set_fd(
		struct io_serial_impl *impl, int fd, const struct termios *ios);

void *
io_serial_alloc(void)
{
	struct io_serial_impl *impl = malloc(sizeof(*impl));
	return impl ? &impl->serial_vptr : NULL;
}

void
io_serial_free(void *ptr)
{
	if (ptr)
		free(io_serial_impl_from_serial(ptr));
}

io_serial_t *
io_serial_init(io_serial_t *serial, io_poll_t *poll, ev_exec_t *exec)
{
	struct io_serial_impl *impl = io_serial_impl_from_serial(serial);
	assert(exec);
	io_ctx_t *ctx = poll ? io_poll_get_ctx(poll) : NULL;

	impl->dev_vptr = &io_serial_impl_dev_vtbl;
	impl->stream_vptr = &io_serial_impl_stream_vtbl;
	impl->serial_vptr = &io_serial_impl_vtbl;

	impl->poll = poll;

	impl->svc = (struct io_svc)IO_SVC_INIT(&io_serial_impl_svc_vtbl);
	impl->ctx = ctx;

	impl->exec = exec;

	impl->watch = (struct io_poll_watch)IO_POLL_WATCH_INIT(
			&io_serial_impl_watch_func);
	impl->readv_task = (struct ev_task)EV_TASK_INIT(
			impl->exec, &io_serial_impl_readv_task_func);
	impl->writev_task = (struct ev_task)EV_TASK_INIT(
			impl->exec, &io_serial_impl_writev_task_func);

#if !LELY_NO_THREADS
	int errsv = pthread_mutex_init(&impl->mtx, NULL);
	if (errsv) {
		errno = errsv;
		return NULL;
	}
#endif

	impl->fd = -1;
	impl->ios = (struct termios){ .c_iflag = 0 };
	impl->rx_timeout = impl->poll ? -1 : LELY_IO_RX_TIMEOUT;
	impl->tx_timeout = impl->poll ? -1 : LELY_IO_TX_TIMEOUT;

	impl->shutdown = 0;
	impl->readv_posted = 0;
	impl->writev_posted = 0;

	sllist_init(&impl->readv_queue);
	impl->current_readv = NULL;

	sllist_init(&impl->writev_queue);
	impl->current_writev = NULL;

	if (impl->ctx)
		io_ctx_insert(impl->ctx, &impl->svc);

	return serial;
}

void
io_serial_fini(io_serial_t *serial)
{
	struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

	io_ctx_remove(impl->ctx, &impl->svc);
	// Cancel all pending tasks.
	io_serial_impl_svc_shutdown(&impl->svc);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&impl->mtx) == EINTR)
		;
	// If necessary, busy-wait until io_serial_impl_readv_task_func() and
	// io_serial_impl_writev_task_func() complete.
	while (impl->readv_posted || impl->writev_posted) {
		if (io_serial_impl_do_abort_tasks(impl))
			continue;
		pthread_mutex_unlock(&impl->mtx);
		do
			sched_yield();
		while (pthread_mutex_lock(&impl->mtx) == EINTR);
	}
	pthread_mutex_unlock(&impl->mtx);
#endif

	// Close the port.
	io_serial_close(serial);

#if !LELY_NO_THREADS
	pthread_mutex_destroy(&impl->mtx);
#endif
}

io_serial_t *
io_serial_create(io_poll_t *poll, ev_exec_t *exec)
{
	int errsv = 0;

	io_serial_t *serial = io_serial_alloc();
	if (!serial) {
		errsv = errno;
		goto error_alloc;
	}

	io_serial_t *tmp = io_serial_init(serial, poll, exec);
	if (!tmp) {
		errsv = errno;
		goto error_init;
	}
	serial = tmp;

	return serial;

error_init:
	io_serial_free((void *)serial);
error_alloc:
	errno = errsv;
	return NULL;
}

void
io_serial_destroy(io_serial_t *serial)
{
	if (serial) {
		io_serial_fini(serial);
		io_serial_free((void *)serial);
	}
}

io_serial_handle_t
io_serial_get_handle(const io_serial_t *serial)
{
	const struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock((pthread_mutex_t *)&impl->mtx) == EINTR)
		;
#endif
	int fd = impl->fd;
#if !LELY_NO_THREADS
	pthread_mutex_unlock((pthread_mutex_t *)&impl->mtx);
#endif
	return fd;
}

int
io_serial_open(io_serial_t *serial, const char *filename)
{
	struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

	int errsv = 0;

	int fd = open(filename, O_RDWR | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
	if (fd == -1) {
		errsv = errno;
		goto error_open;
	}

	struct termios ios = { .c_iflag = 0 };
	if (tcgetattr(fd, &ios) == -1) {
		errsv = errno;
		goto error_tcgetattr;
	}

	// cfmakeraw()
	ios.c_iflag &= ~(BRKINT | ICRNL | IGNBRK | IGNCR | INLCR | ISTRIP | IXON
			| PARMRK);
	ios.c_oflag &= ~OPOST;
	ios.c_cflag &= ~(CSIZE | PARENB);
	ios.c_cflag |= CS8;
	ios.c_lflag &= ~(ECHO | ECHONL | ICANON | IEXTEN | ISIG);
	ios.c_cc[VMIN] = 1;
	ios.c_cc[VTIME] = 0;

	ios.c_iflag |= IGNPAR;
	ios.c_cflag |= CREAD | CLOCAL;

	if (tcsetattr(fd, TCSANOW, &ios) == -1) {
		errsv = errno;
		goto error_tcsetattr;
	}

	fd = io_serial_impl_set_fd(impl, fd, &ios);
	if (fd != -1)
		close(fd);

	return 0;

error_tcsetattr:
error_tcgetattr:
	close(fd);
error_open:
	errno = errsv;
	return -1;
}

int
io_serial_assign(io_serial_t *serial, io_serial_handle_t fd)
{
	struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

	struct termios ios = { .c_iflag = 0 };
	if (tcgetattr(fd, &ios) == -1)
		return -1;

	if (io_fd_set_nonblock(fd) == -1)
		return -1;

	fd = io_serial_impl_set_fd(impl, fd, &ios);
	if (fd != -1)
		close(fd);

	return 0;
}

io_serial_handle_t
io_serial_release(io_serial_t *serial)
{
	struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

	return io_serial_impl_set_fd(impl, -1, NULL);
}

int
io_serial_is_open(const io_serial_t *serial)
{
	return io_serial_get_handle(serial) != -1;
}

int
io_serial_close(io_serial_t *serial)
{
	int fd = io_serial_release(serial);
	return fd != -1 ? close(fd) : 0;
}

static io_ctx_t *
io_serial_impl_dev_get_ctx(const io_dev_t *dev)
{
	const struct io_serial_impl *impl = io_serial_impl_from_dev(dev);

	return impl->ctx;
}

static ev_exec_t *
io_serial_impl_dev_get_exec(const io_dev_t *dev)
{
	const struct io_serial_impl *impl = io_serial_impl_from_dev(dev);

	return impl->exec;
}

static size_t
io_serial_impl_dev_cancel(io_dev_t *dev, struct ev_task *task)
{
	struct io_serial_impl *impl = io_serial_impl_from_dev(dev);
	size_t n = 0;

	struct sllist readv_queue, writev_queue;
	sllist_init(&readv_queue);
	sllist_init(&writev_queue);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&impl->mtx) == EINTR)
		;
#endif
	io_serial_impl_do_pop(impl, &readv_queue, &writev_queue, task);
	// Mark the ongoing read operation as canceled, if necessary.
	if (impl->current_readv && (!task || task == impl->current_readv)) {
		impl->current_readv = NULL;
		n += n < SIZE_MAX;
	}
	// Mark the ongoing write operation as canceled, if necessary.
	if (impl->current_writev && (!task || task == impl->current_writev)) {
		impl->current_writev = NULL;
		n += n < SIZE_MAX;
	}
#if !LELY_NO_THREADS
	pthread_mutex_unlock(&impl->mtx);
#endif

	size_t nreadvmsg =
			io_stream_readv_queue_post(&readv_queue, -1, ECANCELED);
	n = n < SIZE_MAX - nreadvmsg ? n + nreadvmsg : SIZE_MAX;
	size_t nwritevmsg = io_stream_writev_queue_post(
			&writev_queue, -1, ECANCELED);
	n = n < SIZE_MAX - nwritevmsg ? n + nwritevmsg : SIZE_MAX;

	return n;
}

static size_t
io_serial_impl_dev_abort(io_dev_t *dev, struct ev_task *task)
{
	struct io_serial_impl *impl = io_serial_impl_from_dev(dev);

	struct sllist queue;
	sllist_init(&queue);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&impl->mtx) == EINTR)
		;
#endif
	io_serial_impl_do_pop(impl, &queue, &queue, task);
#if !LELY_NO_THREADS
	pthread_mutex_unlock(&impl->mtx);
#endif

	return ev_task_queue_abort(&queue);
}

static io_dev_t *
io_serial_impl_stream_get_dev(const io_stream_t *stream)
{
	const struct io_serial_impl *impl = io_serial_impl_from_stream(stream);

	return &impl->dev_vptr;
}

static ssize_t
io_serial_impl_stream_readv(
		io_stream_t *stream, const struct io_buf *buf, int bufcnt)
{
	struct io_serial_impl *impl = io_serial_impl_from_stream(stream);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&impl->mtx) == EINTR)
		;
#endif
	int fd = impl->fd;
	int timeout = impl->rx_timeout;
#if !LELY_NO_THREADS
	pthread_mutex_unlock(&impl->mtx);
#endif

	return io_fd_readv(fd, (const struct iovec *)buf, bufcnt, timeout);
}

static void
io_serial_impl_stream_submit_readv(
		io_stream_t *stream, struct io_stream_readv *readv)
{
	struct io_serial_impl *impl = io_serial_impl_from_stream(stream);
	assert(readv);
	struct ev_task *task = &readv->task;

	if (!task->exec)
		task->exec = impl->exec;
	ev_exec_on_task_init(task->exec);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&impl->mtx) == EINTR)
		;
#endif
	if (impl->shutdown) {
#if !LELY_NO_THREADS
		pthread_mutex_unlock(&impl->mtx);
#endif
		io_stream_readv_post(readv, -1, ECANCELED);
	} else if (readv->bufcnt <= 0) {
#if !LELY_NO_THREADS
		pthread_mutex_unlock(&impl->mtx);
#endif
		io_stream_readv_post(readv, -1, EINVAL);
	} else {
		int post_readv = !impl->readv_posted
				&& sllist_empty(&impl->readv_queue);
		sllist_push_back(&impl->readv_queue, &task->_node);
		if (post_readv)
			impl->readv_posted = 1;
#if !LELY_NO_THREADS
		pthread_mutex_unlock(&impl->mtx);
#endif
		if (post_readv)
			ev_exec_post(impl->readv_task.exec, &impl->readv_task);
	}
}

static ssize_t
io_serial_impl_stream_writev(
		io_stream_t *stream, const struct io_buf *buf, int bufcnt)
{
	struct io_serial_impl *impl = io_serial_impl_from_stream(stream);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&impl->mtx) == EINTR)
		;
#endif
	int fd = impl->fd;
	int timeout = impl->tx_timeout;
#if !LELY_NO_THREADS
	pthread_mutex_unlock(&impl->mtx);
#endif

	return io_fd_writev(fd, (const struct iovec *)buf, bufcnt, timeout);
}

static void
io_serial_impl_stream_submit_writev(
		io_stream_t *stream, struct io_stream_writev *writev)
{
	struct io_serial_impl *impl = io_serial_impl_from_stream(stream);
	assert(writev);
	struct ev_task *task = &writev->task;

	if (!task->exec)
		task->exec = impl->exec;
	ev_exec_on_task_init(task->exec);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&impl->mtx) == EINTR)
		;
#endif
	if (impl->shutdown) {
#if !LELY_NO_THREADS
		pthread_mutex_unlock(&impl->mtx);
#endif
		io_stream_writev_post(writev, -1, ECANCELED);
	} else if (writev->bufcnt <= 0) {
#if !LELY_NO_THREADS
		pthread_mutex_unlock(&impl->mtx);
#endif
		io_stream_writev_post(writev, -1, EINVAL);
	} else {
		int post_writev = !impl->writev_posted
				&& sllist_empty(&impl->writev_queue);
		sllist_push_back(&impl->writev_queue, &task->_node);
		if (post_writev)
			impl->writev_posted = 1;
#if !LELY_NO_THREADS
		pthread_mutex_unlock(&impl->mtx);
#endif
		if (post_writev)
			ev_exec_post(impl->writev_task.exec,
					&impl->writev_task);
	}
}

static io_stream_t *
io_serial_impl_get_stream(const io_serial_t *serial)
{
	const struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

	return &impl->stream_vptr;
}

static int
io_serial_impl_send_break(io_serial_t *serial)
{
	return tcsendbreak(io_serial_get_handle(serial), 0);
}

static int
io_serial_impl_flush(io_serial_t *serial)
{
	return tcdrain(io_serial_get_handle(serial));
}

static int
io_serial_impl_purge(io_serial_t *serial, int how)
{
	int queue_selector;
	switch (how) {
	case IO_SERIAL_PURGE_RX: queue_selector = TCIFLUSH; break;
	case IO_SERIAL_PURGE_TX: queue_selector = TCOFLUSH; break;
	case IO_SERIAL_PURGE_RXTX: queue_selector = TCIOFLUSH; break;
	default: errno = EINVAL; return -1;
	}

	return tcflush(io_serial_get_handle(serial), queue_selector);
}

static int
io_serial_impl_get_baud_rate(const io_serial_t *serial)
{
	const struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock((pthread_mutex_t *)&impl->mtx) == EINTR)
		;
#endif
	struct termios ios = impl->ios;
#if !LELY_NO_THREADS
	pthread_mutex_unlock((pthread_mutex_t *)&impl->mtx);
#endif

	switch (cfgetospeed(&ios)) {
	case B50: return 50;
	case B75: return 75;
	case B110: return 110;
	case B134: return 134;
	case B150: return 150;
	case B200: return 200;
	case B300: return 300;
	case B600: return 600;
	case B1200: return 1200;
	case B1800: return 1800;
	case B2400: return 2400;
	case B4800: return 4800;
	case B9600: return 9600;
	case B19200: return 19200;
	case B38400: return 38400;
#ifdef B7200
	case B7200: return 7200;
#endif
#ifdef B14400
	case B14400: return 14400;
#endif
#ifdef B57600
	case B57600: return 57600;
#endif
#ifdef B115200
	case B115200: return 115200;
#endif
#ifdef B230400
	case B230400: return 230400;
#endif
#ifdef B460800
	case B460800: return 460800;
#endif
#ifdef B500000
	case B500000: return 500000;
#endif
#ifdef B576000
	case B576000: return 576000;
#endif
#ifdef B921600
	case B921600: return 921600;
#endif
#ifdef B1000000
	case B1000000: return 1000000;
#endif
#ifdef B1152000
	case B1152000: return 1152000;
#endif
#ifdef B2000000
	case B2000000: return 2000000;
#endif
#ifdef B3000000
	case B3000000: return 3000000;
#endif
#ifdef B3500000
	case B3500000: return 3500000;
#endif
#ifdef B4000000
	case B4000000: return 4000000;
#endif
	default: return 0;
	}
}

static int
io_serial_impl_set_baud_rate(io_serial_t *serial, int optval)
{
	struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

	speed_t speed;
	switch (optval) {
	case 0: speed = B0; break;
	case 50: speed = B50; break;
	case 75: speed = B75; break;
	case 110: speed = B110; break;
	case 134: speed = B134; break;
	case 150: speed = B150; break;
	case 200: speed = B200; break;
	case 300: speed = B300; break;
	case 600: speed = B600; break;
	case 1200: speed = B1200; break;
	case 1800: speed = B1800; break;
	case 2400: speed = B2400; break;
	case 4800: speed = B4800; break;
	case 9600: speed = B9600; break;
	case 19200: speed = B19200; break;
	case 38400: speed = B38400; break;
#ifdef B7200
	case 7200: speed = B7200; break;
#endif
#ifdef B14400
	case 14400: speed = B14400; break;
#endif
#ifdef B57600
	case 57600: speed = B57600; break;
#endif
#ifdef B115200
	case 115200: speed = B115200; break;
#endif
#ifdef B230400
	case 230400: speed = B230400; break;
#endif
#ifdef B460800
	case 460800: speed = B460800; break;
#endif
#ifdef B500000
	case 500000: speed = B500000; break;
#endif
#ifdef B576000
	case 576000: speed = B576000; break;
#endif
#ifdef B921600
	case 921600: speed = B921600; break;
#endif
#ifdef B1000000
	case 1000000: speed = B1000000; break;
#endif
#ifdef B1152000
	case 1152000: speed = B1152000; break;
#endif
#ifdef B2000000
	case 2000000: speed = B2000000; break;
#endif
#ifdef B3000000
	case 3000000: speed = B3000000; break;
#endif
#ifdef B3500000
	case 3500000: speed = B3500000; break;
#endif
#ifdef B4000000
	case 4000000: speed = B4000000; break;
#endif
	default: errno = EINVAL; return -1;
	}

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&impl->mtx) == EINTR)
		;
#endif
	struct termios ios = impl->ios;

	if (cfsetispeed(&ios, speed) == -1) {
#if !LELY_NO_THREADS
		pthread_mutex_unlock(&impl->mtx);
#endif
		return -1;
	}

	if (cfsetospeed(&ios, speed) == -1) {
#if !LELY_NO_THREADS
		pthread_mutex_unlock(&impl->mtx);
#endif
		return -1;
	}

	if (tcsetattr(impl->fd, TCSANOW, &ios) == -1) {
#if !LELY_NO_THREADS
		pthread_mutex_unlock(&impl->mtx);
#endif
		return -1;
	}

	impl->ios = ios;
#if !LELY_NO_THREADS
	pthread_mutex_unlock(&impl->mtx);
#endif

	return 0;
}

static int
io_serial_impl_get_flow_ctrl(const io_serial_t *serial)
{
	const struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock((pthread_mutex_t *)&impl->mtx) == EINTR)
		;
#endif
	struct termios ios = impl->ios;
#if !LELY_NO_THREADS
	pthread_mutex_unlock((pthread_mutex_t *)&impl->mtx);
#endif

	if (ios.c_iflag & (IXOFF | IXON))
		return IO_SERIAL_FLOW_CTRL_SW;
#ifdef CRTSCTS
	if (ios.c_cflag & CRTSCTS)
		return IO_SERIAL_FLOW_CTRL_HW;
#endif
	return IO_SERIAL_FLOW_CTRL_NONE;
}

static int
io_serial_impl_set_flow_ctrl(io_serial_t *serial, int optval)
{
	struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&impl->mtx) == EINTR)
		;
#endif
	struct termios ios = impl->ios;

	switch (optval) {
	case IO_SERIAL_FLOW_CTRL_NONE: ios.c_iflag &= ~(IXOFF | IXON);
#ifdef CRTSCTS
		ios.c_cflag &= ~CRTSCTS;
#endif
		break;
	case IO_SERIAL_FLOW_CTRL_SW: ios.c_iflag |= IXOFF | IXON;
#ifdef CRTSCTS
		ios.c_cflag &= ~CRTSCTS;
#endif
		break;
#ifdef CRTSCTS
	case IO_SERIAL_FLOW_CTRL_HW:
		ios.c_iflag &= ~(IXOFF | IXON);
		ios.c_cflag |= CRTSCTS;
		break;
#endif
	default:
#if !LELY_NO_THREADS
		pthread_mutex_unlock(&impl->mtx);
#endif
		errno = EINVAL;
		return -1;
	}

	if (tcsetattr(impl->fd, TCSANOW, &ios) == -1) {
#if !LELY_NO_THREADS
		pthread_mutex_unlock(&impl->mtx);
#endif
		return -1;
	}

	impl->ios = ios;
#if !LELY_NO_THREADS
	pthread_mutex_unlock(&impl->mtx);
#endif

	return 0;
}

static int
io_serial_impl_get_parity(const io_serial_t *serial)
{
	const struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock((pthread_mutex_t *)&impl->mtx) == EINTR)
		;
#endif
	struct termios ios = impl->ios;
#if !LELY_NO_THREADS
	pthread_mutex_unlock((pthread_mutex_t *)&impl->mtx);
#endif

	if (ios.c_cflag & PARENB) {
		if (ios.c_cflag & PARODD)
			return IO_SERIAL_PARITY_ODD;
		else
			return IO_SERIAL_PARITY_EVEN;
	}
	return IO_SERIAL_PARITY_NONE;
}

static int
io_serial_impl_set_parity(io_serial_t *serial, int optval)
{
	struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&impl->mtx) == EINTR)
		;
#endif
	struct termios ios = impl->ios;

	switch (optval) {
	case IO_SERIAL_PARITY_NONE:
		ios.c_iflag |= IGNPAR;
		ios.c_cflag &= ~(PARENB | PARODD);
		break;
	case IO_SERIAL_PARITY_ODD:
		ios.c_iflag &= ~(IGNPAR | PARMRK);
		ios.c_iflag |= INPCK;
		ios.c_cflag |= PARENB | PARODD;
		break;
	case IO_SERIAL_PARITY_EVEN:
		ios.c_iflag &= ~(IGNPAR | PARMRK);
		ios.c_iflag |= INPCK;
		ios.c_cflag |= PARENB;
		ios.c_cflag &= ~PARODD;
		break;
	default:
#if !LELY_NO_THREADS
		pthread_mutex_unlock(&impl->mtx);
#endif
		errno = EINVAL;
		return -1;
	}

	if (tcsetattr(impl->fd, TCSANOW, &ios) == -1) {
#if !LELY_NO_THREADS
		pthread_mutex_unlock(&impl->mtx);
#endif
		return -1;
	}

	impl->ios = ios;
#if !LELY_NO_THREADS
	pthread_mutex_unlock(&impl->mtx);
#endif

	return 0;
}

static int
io_serial_impl_get_stop_bits(const io_serial_t *serial)
{
	const struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock((pthread_mutex_t *)&impl->mtx) == EINTR)
		;
#endif
	struct termios ios = impl->ios;
#if !LELY_NO_THREADS
	pthread_mutex_unlock((pthread_mutex_t *)&impl->mtx);
#endif

	if (ios.c_cflag & CSTOPB)
		return IO_SERIAL_STOP_BITS_TWO;
	return IO_SERIAL_STOP_BITS_ONE;
}

static int
io_serial_impl_set_stop_bits(io_serial_t *serial, int optval)
{
	struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&impl->mtx) == EINTR)
		;
#endif
	struct termios ios = impl->ios;

	switch (optval) {
	case IO_SERIAL_STOP_BITS_ONE: ios.c_cflag &= ~CSTOPB; break;
	case IO_SERIAL_STOP_BITS_TWO: ios.c_cflag |= CSTOPB; break;
	default:
#if !LELY_NO_THREADS
		pthread_mutex_unlock(&impl->mtx);
#endif
		errno = EINVAL;
		return -1;
	}

	if (tcsetattr(impl->fd, TCSANOW, &ios) == -1) {
#if !LELY_NO_THREADS
		pthread_mutex_unlock(&impl->mtx);
#endif
		return -1;
	}

	impl->ios = ios;
#if !LELY_NO_THREADS
	pthread_mutex_unlock(&impl->mtx);
#endif

	return 0;
}

static int
io_serial_impl_get_char_size(const io_serial_t *serial)
{
	const struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock((pthread_mutex_t *)&impl->mtx) == EINTR)
		;
#endif
	struct termios ios = impl->ios;
#if !LELY_NO_THREADS
	pthread_mutex_unlock((pthread_mutex_t *)&impl->mtx);
#endif

	switch (ios.c_cflag & CSIZE) {
	case CS5: return 5;
	case CS6: return 6;
	case CS7: return 7;
	case CS8:
	default: return 8;
	}
}

static int
io_serial_impl_set_char_size(io_serial_t *serial, int optval)
{
	struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&impl->mtx) == EINTR)
		;
#endif
	struct termios ios = impl->ios;

	ios.c_cflag &= ~CSIZE;
	switch (optval) {
	case 5: ios.c_cflag |= CS5; break;
	case 6: ios.c_cflag |= CS6; break;
	case 7: ios.c_cflag |= CS7; break;
	case 8: ios.c_cflag |= CS8; break;
	default:
#if !LELY_NO_THREADS
		pthread_mutex_unlock(&impl->mtx);
#endif
		errno = EINVAL;
		return -1;
	}

	if (tcsetattr(impl->fd, TCSANOW, &ios) == -1) {
#if !LELY_NO_THREADS
		pthread_mutex_unlock(&impl->mtx);
#endif
		return -1;
	}

	impl->ios = ios;
#if !LELY_NO_THREADS
	pthread_mutex_unlock(&impl->mtx);
#endif

	return 0;
}

static int
io_serial_impl_get_rx_timeout(const io_serial_t *serial)
{
	const struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock((pthread_mutex_t *)&impl->mtx) == EINTR)
		;
#endif
	int optval = impl->rx_timeout;
#if !LELY_NO_THREADS
	pthread_mutex_unlock((pthread_mutex_t *)&impl->mtx);
#endif

	return optval;
}

static int
io_serial_impl_set_rx_timeout(io_serial_t *serial, int optval)
{
	struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&impl->mtx) == EINTR)
		;
#endif
	impl->rx_timeout = optval;
#if !LELY_NO_THREADS
	pthread_mutex_unlock(&impl->mtx);
#endif

	return 0;
}

static int
io_serial_impl_get_tx_timeout(const io_serial_t *serial)
{
	const struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock((pthread_mutex_t *)&impl->mtx) == EINTR)
		;
#endif
	int optval = impl->tx_timeout;
#if !LELY_NO_THREADS
	pthread_mutex_unlock((pthread_mutex_t *)&impl->mtx);
#endif

	return optval;
}

static int
io_serial_impl_set_tx_timeout(io_serial_t *serial, int optval)
{
	struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&impl->mtx) == EINTR)
		;
#endif
	impl->tx_timeout = optval;
#if !LELY_NO_THREADS
	pthread_mutex_unlock(&impl->mtx);
#endif

	return 0;
}

static void
io_serial_impl_svc_shutdown(struct io_svc *svc)
{
	struct io_serial_impl *impl = io_serial_impl_from_svc(svc);
	io_dev_t *dev = &impl->dev_vptr;

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&impl->mtx) == EINTR)
		;
#endif
	int shutdown = !impl->shutdown;
	impl->shutdown = 1;
	if (shutdown) {
		if (impl->poll && impl->fd != -1)
			// Stop monitoring I/O events.
			io_poll_watch(impl->poll, impl->fd, 0, &impl->watch);
		// Try to abort io_serial_impl_readv_task_func() and
		// io_serial_impl_writev_task_func().
		io_serial_impl_do_abort_tasks(impl);
	}
#if !LELY_NO_THREADS
	pthread_mutex_unlock(&impl->mtx);
#endif

	if (shutdown)
		// Cancel all pending operations.
		io_serial_impl_dev_cancel(dev, NULL);
}

static void
io_serial_impl_watch_func(struct io_poll_watch *watch, int events)
{
	assert(watch);
	struct io_serial_impl *impl =
			structof(watch, struct io_serial_impl, watch);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&impl->mtx) == EINTR)
		;
#endif
	// Retry any pending read operations.
	int post_readv = 0;
	if ((events & (IO_EVENT_IN | IO_EVENT_ERR))
			&& !sllist_empty(&impl->readv_queue)
			&& !impl->shutdown) {
		post_readv = !impl->readv_posted;
		impl->readv_posted = 1;
	}

	// Retry any pending write operations.
	int post_writev = 0;
	if ((events & (IO_EVENT_OUT | IO_EVENT_ERR))
			&& !sllist_empty(&impl->writev_queue)
			&& !impl->shutdown) {
		post_writev = !impl->writev_posted;
		impl->writev_posted = 1;
	}
#if !LELY_NO_THREADS
	pthread_mutex_unlock(&impl->mtx);
#endif

	if (post_readv)
		ev_exec_post(impl->readv_task.exec, &impl->readv_task);
	if (post_writev)
		ev_exec_post(impl->writev_task.exec, &impl->writev_task);
}

static void
io_serial_impl_readv_task_func(struct ev_task *task)
{
	assert(task);
	struct io_serial_impl *impl =
			structof(task, struct io_serial_impl, readv_task);

	int errsv = errno;

	struct io_stream_readv *readv = NULL;
	int wouldblock = 0;

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&impl->mtx) == EINTR)
		;
#endif
	// Try to process all pending read operations at once, unless we're in
	// blocking mode.
	while ((task = impl->current_readv = ev_task_from_node(
				sllist_pop_front(&impl->readv_queue)))) {
		readv = io_stream_readv_from_task(task);
		int fd = impl->fd;
		// The timeout is per buffer.
		int timeout = impl->rx_timeout;
		if (timeout > 0 && readv->bufcnt > 1)
			timeout = timeout < INT_MAX / readv->bufcnt
					? timeout * readv->bufcnt
					: INT_MAX;
		// Use blocking mode in case of a non-negative timeout.
		int nonblock = impl->poll && timeout < 0;
#if !LELY_NO_THREADS
		pthread_mutex_unlock(&impl->mtx);
#endif
		ssize_t result = io_fd_readv(fd,
				(const struct iovec *)readv->buf, readv->bufcnt,
				nonblock ? 0 : timeout);
		int errc = result >= 0 ? 0 : errno;
		wouldblock = (errc == EAGAIN || errc == EWOULDBLOCK)
				&& nonblock;
		if (!wouldblock)
			// The operation succeeded or failed immediately.
			io_stream_readv_post(readv, result, errc);
#if !LELY_NO_THREADS
		while (pthread_mutex_lock(&impl->mtx) == EINTR)
			;
#endif
		if (task == impl->current_readv) {
			// Put the read operation back on the queue if it would
			// block, unless it was canceled.
			if (wouldblock) {
				sllist_push_front(&impl->readv_queue,
						&task->_node);
				task = NULL;
			}
			impl->current_readv = NULL;
		}
		assert(!impl->current_readv);
		// Stop if the operation did or would block.
		if (!nonblock || wouldblock)
			break;
	}
	// If the operation would block, start watching the file descriptor.
	// (unless it has been closed in the mean time).
	if (impl->poll && wouldblock && !sllist_empty(&impl->readv_queue)
			&& impl->fd != -1 && !impl->shutdown) {
		int events = IO_EVENT_IN;
		if (!impl->writev_posted && !sllist_empty(&impl->writev_queue))
			events |= IO_EVENT_OUT;
		io_poll_watch(impl->poll, impl->fd, events, &impl->watch);
	}
	// Repost this task if any read operations remain in the queue, unless
	// we're waiting the file descriptor to become ready.
	int post_readv = impl->readv_posted = !sllist_empty(&impl->readv_queue)
			&& !(impl->poll && wouldblock) && !impl->shutdown;
#if !LELY_NO_THREADS
	pthread_mutex_unlock(&impl->mtx);
#endif

	if (task && wouldblock)
		// The operation would block but was canceled before it could be
		// requeued.
		io_stream_readv_post(
				io_stream_readv_from_task(task), -1, ECANCELED);

	if (post_readv)
		ev_exec_post(impl->readv_task.exec, &impl->readv_task);

	errno = errsv;
}

static void
io_serial_impl_writev_task_func(struct ev_task *task)
{
	assert(task);
	struct io_serial_impl *impl =
			structof(task, struct io_serial_impl, writev_task);

	int errsv = errno;

	struct io_stream_writev *writev = NULL;
	int wouldblock = 0;

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&impl->mtx) == EINTR)
		;
#endif
	// Try to process all pending write operations at once, unless we're in
	// blocking mode.
	while ((task = impl->current_writev = ev_task_from_node(
				sllist_pop_front(&impl->writev_queue)))) {
		writev = io_stream_writev_from_task(task);
		int fd = impl->fd;
		// The timeout is per buffer.
		int timeout = impl->tx_timeout;
		if (timeout > 0 && writev->bufcnt > 1)
			timeout = timeout < INT_MAX / writev->bufcnt
					? timeout * writev->bufcnt
					: INT_MAX;
		// Use blocking mode in case of a non-negative timeout.
		int nonblock = impl->poll && timeout < 0;
#if !LELY_NO_THREADS
		pthread_mutex_unlock(&impl->mtx);
#endif
		ssize_t result = io_fd_writev(fd,
				(const struct iovec *)writev->buf,
				writev->bufcnt, nonblock ? 0 : timeout);
		int errc = result >= 0 ? 0 : errno;
		wouldblock = (errc == EAGAIN || errc == EWOULDBLOCK)
				&& nonblock;
		if (!wouldblock)
			// The operation succeeded or failed immediately.
			io_stream_writev_post(writev, result, errc);
#if !LELY_NO_THREADS
		while (pthread_mutex_lock(&impl->mtx) == EINTR)
			;
#endif
		if (task == impl->current_writev) {
			// Put the write operation back on the queue if it would
			// block, unless it was canceled.
			if (wouldblock) {
				sllist_push_front(&impl->writev_queue,
						&task->_node);
				task = NULL;
			}
			impl->current_writev = NULL;
		}
		assert(!impl->current_writev);
		// Stop if the operation did or would block.
		if (!nonblock || wouldblock)
			break;
	}
	// If the operation would block, start watching the file descriptor.
	// (unless it has been closed in the mean time).
	if (impl->poll && wouldblock && !sllist_empty(&impl->writev_queue)
			&& impl->fd != -1 && !impl->shutdown) {
		int events = IO_EVENT_OUT;
		if (!impl->readv_posted && !sllist_empty(&impl->readv_queue))
			events |= IO_EVENT_IN;
		io_poll_watch(impl->poll, impl->fd, events, &impl->watch);
	}
	// Repost this task if any write operations remain in the queue, unless
	// we're waiting the file descriptor to become ready.
	int post_writev = impl->writev_posted =
			!sllist_empty(&impl->writev_queue)
			&& !(impl->poll && wouldblock) && !impl->shutdown;
#if !LELY_NO_THREADS
	pthread_mutex_unlock(&impl->mtx);
#endif

	if (task || wouldblock)
		// The operation would block but was canceled before it could be
		// requeued.
		io_stream_writev_post(io_stream_writev_from_task(task), -1,
				ECANCELED);

	if (post_writev)
		ev_exec_post(impl->writev_task.exec, &impl->writev_task);

	errno = errsv;
}

static inline struct io_serial_impl *
io_serial_impl_from_dev(const io_dev_t *dev)
{
	assert(dev);

	return structof(dev, struct io_serial_impl, dev_vptr);
}

static inline struct io_serial_impl *
io_serial_impl_from_stream(const io_stream_t *stream)
{
	assert(stream);

	return structof(stream, struct io_serial_impl, stream_vptr);
}

static inline struct io_serial_impl *
io_serial_impl_from_serial(const io_serial_t *serial)
{
	assert(serial);

	return structof(serial, struct io_serial_impl, serial_vptr);
}

static inline struct io_serial_impl *
io_serial_impl_from_svc(const struct io_svc *svc)
{
	assert(svc);

	return structof(svc, struct io_serial_impl, svc);
}

static void
io_serial_impl_do_pop(struct io_serial_impl *impl, struct sllist *readv_queue,
		struct sllist *writev_queue, struct ev_task *task)
{
	assert(impl);
	assert(readv_queue);
	assert(writev_queue);

	if (!task) {
		sllist_append(readv_queue, &impl->readv_queue);
		sllist_append(writev_queue, &impl->writev_queue);
	} else if (sllist_remove(&impl->readv_queue, &task->_node)) {
		sllist_push_back(readv_queue, &task->_node);
	} else if (sllist_remove(&impl->writev_queue, &task->_node)) {
		sllist_push_back(writev_queue, &task->_node);
	}
}

static size_t
io_serial_impl_do_abort_tasks(struct io_serial_impl *impl)
{
	assert(impl);

	size_t n = 0;

	// Try to abort io_serial_impl_readv_task_func().
	// clang-format off
	if (impl->readv_posted && ev_exec_abort(impl->readv_task.exec,
			&impl->readv_task)) {
		// clang-format on
		impl->readv_posted = 0;
		n++;
	}

	// Try to abort io_serial_impl_writev_task_func().
	// clang-format off
	if (impl->writev_posted && ev_exec_abort(impl->writev_task.exec,
			&impl->writev_task)) {
		// clang-format on
		impl->writev_posted = 0;
		n++;
	}

	return n;
}

static int
io_serial_impl_set_fd(
		struct io_serial_impl *impl, int fd, const struct termios *ios)
{
	assert(impl);

	struct sllist readv_queue, writev_queue;
	sllist_init(&readv_queue);
	sllist_init(&writev_queue);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&impl->mtx) == EINTR)
		;
#endif

	if (impl->fd != -1 && !impl->shutdown && impl->poll)
		// Stop monitoring I/O events.
		io_poll_watch(impl->poll, impl->fd, 0, &impl->watch);

	int tmp = impl->fd;
	impl->fd = fd;
	fd = tmp;

	impl->ios = ios ? *ios : (struct termios){ .c_iflag = 0 };
	impl->rx_timeout = impl->poll ? -1 : LELY_IO_RX_TIMEOUT;
	impl->tx_timeout = impl->poll ? -1 : LELY_IO_TX_TIMEOUT;

	// Cancel pending operations.
	sllist_append(&readv_queue, &impl->readv_queue);
	sllist_append(&writev_queue, &impl->writev_queue);

	// Mark the ongoing read and write operations as canceled, if necessary.
	impl->current_readv = NULL;
	impl->current_writev = NULL;

#if !LELY_NO_THREADS
	pthread_mutex_unlock(&impl->mtx);
#endif

	io_stream_readv_queue_post(&readv_queue, -1, ECANCELED);
	io_stream_writev_queue_post(&writev_queue, -1, ECANCELED);

	return fd;
}

#endif // _POSIX_C_SOURCE >= 200112L
