/**@file
 * This file is part of the I/O library; it contains the system serial port
 * implementation for Windows.
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

#if _WIN32

#include "../stream.h"
#include <lely/io2/ctx.h>
#include <lely/io2/sys/serial.h>
#include <lely/io2/win32/poll.h>
#include <lely/util/errnum.h>
#include <lely/util/util.h>

#include <assert.h>
#include <stdlib.h>

static ssize_t io_serial_fd_readv(
		HANDLE fd, const struct io_buf *buf, int bufcnt);
static ssize_t io_serial_fd_writev(
		HANDLE fd, const struct io_buf *buf, int bufcnt);

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
	/// The task responsible for intiating read operations.
	struct ev_task readv_task;
	/// The task responsible for intiating write operations.
	struct ev_task writev_task;
#if !LELY_NO_THREADS
	/**
	 * The critical section protecting the handle and the queues of pending
	 * operations.
	 */
	CRITICAL_SECTION CriticalSection;
#endif
	/// The native handle.
	HANDLE hFile;
	/// The control setting for a serial port.
	DCB DCB;
	/// The time-out parameters for a serial port.
	COMMTIMEOUTS CommTimeouts;
	/**
	 * A flag indicating whether #hFile was opened with
	 * FILE_FLAG_OVERLAPPED (and #poll != NULL).
	 */
	unsigned async : 1;
	/// A flag indicating whether the I/O service has been shut down.
	unsigned shutdown : 1;
	/// A flag indicating whether #readv_task has been posted to #exec.
	unsigned readv_posted : 1;
	/// A flag indicating whether #writev_task has been posted to #exec.
	unsigned writev_posted : 1;
	/// The queue containing pending read operations.
	struct sllist readv_queue;
	/**
	 * The queue containing successfully initiated read operations waiting
	 * for a completion packet.
	 */
	struct sllist readv_iocp_queue;
	/// The queue containing pending write operations.
	struct sllist writev_queue;
	/**
	 * The queue containing successfully initiated write operations waiting
	 * for a completion packet.
	 */
	struct sllist writev_iocp_queue;
};

static void io_serial_impl_readv_task_func(struct ev_task *task);
static int io_serial_impl_do_readv(
		struct io_stream_readv *readv, size_t nbytes, int errc);
static void io_serial_impl_readv_cp_func(
		struct io_cp *cp, size_t nbytes, int errc);

static void io_serial_impl_writev_task_func(struct ev_task *task);
static int io_serial_impl_do_writev(
		struct io_stream_writev *writev, size_t nbytes, int errc);
static void io_serial_impl_writev_cp_func(
		struct io_cp *cp, size_t nbytes, int errc);

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
static size_t io_serial_impl_do_cancel_iocp(
		struct io_serial_impl *impl, struct ev_task *task);

static HANDLE io_serial_impl_set_handle(struct io_serial_impl *impl,
		HANDLE hFile, LPDCB lpDCB, BOOL bAsync);

static void io_serial_impl_set_timeouts(const struct io_serial_impl *impl,
		LPCOMMTIMEOUTS lpCommTimeouts);

void *
io_serial_alloc(void)
{
	struct io_serial_impl *impl = malloc(sizeof(*impl));
	if (!impl) {
		set_errc(errno2c(errno));
		return NULL;
	}
	return &impl->serial_vptr;
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

	impl->readv_task = (struct ev_task)EV_TASK_INIT(
			impl->exec, &io_serial_impl_readv_task_func);
	impl->writev_task = (struct ev_task)EV_TASK_INIT(
			impl->exec, &io_serial_impl_writev_task_func);

#if !LELY_NO_THREADS
	InitializeCriticalSection(&impl->CriticalSection);
#endif

	impl->hFile = INVALID_HANDLE_VALUE;
	impl->DCB = (DCB){ .DCBlength = sizeof(DCB) };
	io_serial_impl_set_timeouts(impl, &impl->CommTimeouts);

	impl->async = 0;
	impl->shutdown = 0;
	impl->readv_posted = 0;
	impl->writev_posted = 0;

	sllist_init(&impl->readv_queue);
	sllist_init(&impl->readv_iocp_queue);

	sllist_init(&impl->writev_queue);
	sllist_init(&impl->writev_iocp_queue);

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

	// Abort ongoing read and write operations.
	if (impl->hFile != INVALID_HANDLE_VALUE)
		PurgeComm(impl->hFile, PURGE_RXABORT | PURGE_TXABORT);

#if !LELY_NO_THREADS
	EnterCriticalSection(&impl->CriticalSection);
	// If necessary, busy-wait until io_serial_impl_readv_task_func() and
	// io_serial_impl_writev_task_func() complete.
	while (impl->readv_posted || impl->writev_posted) {
		if (io_serial_impl_do_abort_tasks(impl))
			continue;
		LeaveCriticalSection(&impl->CriticalSection);
		SwitchToThread();
		EnterCriticalSection(&impl->CriticalSection);
	}
	LeaveCriticalSection(&impl->CriticalSection);
#endif

	// TODO: Find a reliable way to wait for io_serial_impl_readv_cp_func()
	// and io_serial_impl_writev_cp_func() to complete.

	// Close the port.
	io_serial_close(serial);

#if !LELY_NO_THREADS
	DeleteCriticalSection(&impl->CriticalSection);
#endif
}

io_serial_t *
io_serial_create(io_poll_t *poll, ev_exec_t *exec)
{
	DWORD dwErrCode = 0;

	io_serial_t *serial = io_serial_alloc();
	if (!serial) {
		dwErrCode = GetLastError();
		goto error_alloc;
	}

	io_serial_t *tmp = io_serial_init(serial, poll, exec);
	if (!tmp) {
		dwErrCode = GetLastError();
		goto error_init;
	}
	serial = tmp;

	return serial;

error_init:
	io_serial_free((void *)serial);
error_alloc:
	SetLastError(dwErrCode);
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
	EnterCriticalSection((LPCRITICAL_SECTION)&impl->CriticalSection);
#endif
	HANDLE hFile = impl->hFile;
#if !LELY_NO_THREADS
	LeaveCriticalSection((LPCRITICAL_SECTION)&impl->CriticalSection);
#endif
	return hFile;
}

int
io_serial_open(io_serial_t *serial, const char *filename)
{
	struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

	DWORD dwErrCode = 0;

	HANDLE hFile = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, 0,
			NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		dwErrCode = GetLastError();
		goto error_CreateFileA;
	}

	DCB DCB = { .DCBlength = sizeof(DCB) };
	if (!GetCommState(hFile, &DCB)) {
		dwErrCode = GetLastError();
		goto error_GetCommState;
	}

	// Set some options to emulate the effect of cfmakeraw().
	DCB.fBinary = TRUE;
	DCB.fParity = FALSE;
	DCB.fOutxDsrFlow = FALSE;
	DCB.fDtrControl = DTR_CONTROL_ENABLE;
	DCB.fDsrSensitivity = FALSE;
	DCB.fTXContinueOnXoff = TRUE;
	DCB.fOutX = FALSE;
	DCB.fErrorChar = FALSE;
	DCB.fNull = FALSE;
	DCB.fAbortOnError = FALSE;
	DCB.ByteSize = 8;
	DCB.Parity = NOPARITY;
	DCB.ErrorChar = 0;
	DCB.EofChar = 0;

	if (!SetCommState(hFile, &DCB)) {
		dwErrCode = GetLastError();
		goto error_SetCommState;
	}

	// Set time-out parameters so that the serial port will behave similarly
	// to a network socket.
	COMMTIMEOUTS CommTimeouts;
	io_serial_impl_set_timeouts(impl, &CommTimeouts);
	if (!SetCommTimeouts(hFile, &CommTimeouts)) {
		dwErrCode = GetLastError();
		goto error_SetCommTimeouts;
	}

	if (impl->poll && io_poll_register_handle(impl->poll, hFile) == -1) {
		dwErrCode = GetLastError();
		goto error_register_handle;
	}

	hFile = io_serial_impl_set_handle(impl, hFile, &DCB, TRUE);
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);

	return 0;

error_register_handle:
error_SetCommTimeouts:
error_SetCommState:
error_GetCommState:
	CloseHandle(hFile);
error_CreateFileA:
	SetLastError(dwErrCode);
	return -1;
}

int
io_serial_assign(io_serial_t *serial, io_serial_handle_t fd)
{
	struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

	DCB DCB = { .DCBlength = sizeof(DCB) };
	if (!GetCommState(fd, &DCB))
		return -1;

	// Check if the handle was opened with FILE_FLAG_OVERLAPPED. If
	// NtQueryInformationFile() returns an error, optimistically assume that
	// it was.
	BOOL bAsync = TRUE;
	IO_STATUS_BLOCK IoStatusBlock;
	FILE_MODE_INFORMATION Information = { .Mode = 0 };
	NTSTATUS Status = lpfnNtQueryInformationFile(fd, &IoStatusBlock,
			&Information, sizeof(Information), FileModeInformation);
	if (NT_SUCCESS(Status)) {
		if (Information.Mode & FILE_SYNCHRONOUS_IO_ALERT)
			bAsync = FALSE;
		if (Information.Mode & FILE_SYNCHRONOUS_IO_NONALERT)
			bAsync = FALSE;
	}

	// Set time-out parameters so that the serial port will behave similarly
	// to a network socket.
	COMMTIMEOUTS CommTimeouts;
	io_serial_impl_set_timeouts(impl, &CommTimeouts);
	if (!SetCommTimeouts(fd, &CommTimeouts))
		return -1;

	if (impl->poll && io_poll_register_handle(impl->poll, fd) == -1)
		return -1;

	fd = io_serial_impl_set_handle(impl, fd, &DCB, bAsync);
	if (fd != INVALID_HANDLE_VALUE)
		CloseHandle(fd);

	return 0;
}

io_serial_handle_t
io_serial_release(io_serial_t *serial)
{
	struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

	return io_serial_impl_set_handle(
			impl, INVALID_HANDLE_VALUE, NULL, FALSE);
}

int
io_serial_is_open(const io_serial_t *serial)
{
	return io_serial_get_handle(serial) != INVALID_HANDLE_VALUE;
}

int
io_serial_close(io_serial_t *serial)
{
	HANDLE hFile = io_serial_release(serial);
	if (hFile != INVALID_HANDLE_VALUE)
		return CloseHandle(hFile) ? 0 : -1;
	return 0;
}

static ssize_t
io_serial_fd_readv(HANDLE fd, const struct io_buf *buf, int bufcnt)
{
	ssize_t n = io_buf_size(buf, bufcnt);
	if (n <= 0)
		return n;

	HANDLE hEvent = io_win32_tls_get_event();
	if (!hEvent)
		return -1;
	// Prevent the I/O completion from being queued to the I/O completion
	// port.
	OVERLAPPED Overlapped = { .hEvent = (HANDLE)((UINT_PTR)hEvent | 1) };

	ssize_t result = 0;
	for (int i = 0; i < bufcnt; i++) {
		DWORD dwNumberOfBytesRead = 0;
		DWORD dwErrCode = GetLastError();
		// clang-format off
		if (!ReadFile(fd, buf[i].base, buf[i].len, &dwNumberOfBytesRead,
				&Overlapped)) {
			// clang-format on
			if (GetLastError() != ERROR_IO_PENDING) {
				if (!result)
					result = -1;
				break;
			}
			SetLastError(dwErrCode);
			// clang-format off
			if (!GetOverlappedResult(fd, &Overlapped,
					&dwNumberOfBytesRead, TRUE)) {
				// clang-format on
				if (!result)
					result = -1;
				break;
			}
		}
		assert(result <= (ssize_t)(SSIZE_MAX - dwNumberOfBytesRead));
		result += dwNumberOfBytesRead;
		if (dwNumberOfBytesRead < buf[i].len)
			break;
	}
	return result;
}

static ssize_t
io_serial_fd_writev(HANDLE fd, const struct io_buf *buf, int bufcnt)
{
	ssize_t n = io_buf_size(buf, bufcnt);
	if (n <= 0)
		return n;

	HANDLE hEvent = io_win32_tls_get_event();
	if (!hEvent)
		return -1;
	// Prevent the I/O completion from being queued to the I/O completion
	// port.
	OVERLAPPED Overlapped = { .hEvent = (HANDLE)((UINT_PTR)hEvent | 1) };

	ssize_t result = 0;
	for (int i = 0; i < bufcnt; i++) {
		DWORD dwNumberOfBytesWritten = 0;
		DWORD dwErrCode = GetLastError();
		// clang-format off
		if (!WriteFile(fd, buf[i].base, buf[i].len,
				&dwNumberOfBytesWritten, &Overlapped)) {
			// clang-format on
			if (GetLastError() != ERROR_IO_PENDING) {
				if (!result)
					result = -1;
				break;
			}
			SetLastError(dwErrCode);
			// clang-format off
			if (!GetOverlappedResult(fd, &Overlapped,
					&dwNumberOfBytesWritten, TRUE)) {
				// clang-format on
				if (!result)
					result = -1;
				break;
			}
		}
		assert(result <= (ssize_t)(SSIZE_MAX - dwNumberOfBytesWritten));
		result += dwNumberOfBytesWritten;
		if (dwNumberOfBytesWritten < buf[i].len)
			break;
	}
	return result;
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
	EnterCriticalSection(&impl->CriticalSection);
#endif
	io_serial_impl_do_pop(impl, &readv_queue, &writev_queue, task);
	// Cancel operations waiting for a completion packet.
	n = io_serial_impl_do_cancel_iocp(impl, task);
#if !LELY_NO_THREADS
	LeaveCriticalSection(&impl->CriticalSection);
#endif

	size_t nreadvmsg = io_stream_readv_queue_post(
			&readv_queue, -1, ERROR_OPERATION_ABORTED);
	n = n < SIZE_MAX - nreadvmsg ? n + nreadvmsg : SIZE_MAX;
	size_t nwritevmsg = io_stream_writev_queue_post(
			&writev_queue, -1, ERROR_OPERATION_ABORTED);
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
	EnterCriticalSection(&impl->CriticalSection);
#endif
	io_serial_impl_do_pop(impl, &queue, &queue, task);
#if !LELY_NO_THREADS
	LeaveCriticalSection(&impl->CriticalSection);
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

	return io_serial_fd_readv(
			io_serial_get_handle(&impl->serial_vptr), buf, bufcnt);
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

	DWORD dwErrCode = GetLastError();
	ssize_t n = io_buf_size(readv->buf, readv->bufcnt);
	if (n < 0) {
		io_stream_readv_post(readv, -1, GetLastError());
		SetLastError(dwErrCode);
		return;
	}

#if !LELY_NO_THREADS
	EnterCriticalSection(&impl->CriticalSection);
#endif
	if (impl->shutdown) {
#if !LELY_NO_THREADS
		LeaveCriticalSection(&impl->CriticalSection);
#endif
		io_stream_readv_post(readv, -1, ERROR_OPERATION_ABORTED);
	} else if (readv->bufcnt <= 0) {
#if !LELY_NO_THREADS
		LeaveCriticalSection(&impl->CriticalSection);
#endif
		io_stream_readv_post(readv, -1, ERROR_INVALID_PARAMETER);
	} else {
		int post_readv = !impl->readv_posted
				&& sllist_empty(&impl->readv_queue);
		sllist_push_back(&impl->readv_queue, &task->_node);
		if (post_readv)
			impl->readv_posted = 1;
#if !LELY_NO_THREADS
		LeaveCriticalSection(&impl->CriticalSection);
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

	return io_serial_fd_writev(
			io_serial_get_handle(&impl->serial_vptr), buf, bufcnt);
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

	DWORD dwErrCode = GetLastError();
	ssize_t n = io_buf_size(writev->buf, writev->bufcnt);
	if (n < 0) {
		io_stream_writev_post(writev, -1, GetLastError());
		SetLastError(dwErrCode);
		return;
	}

#if !LELY_NO_THREADS
	EnterCriticalSection(&impl->CriticalSection);
#endif
	if (impl->shutdown) {
#if !LELY_NO_THREADS
		LeaveCriticalSection(&impl->CriticalSection);
#endif
		io_stream_writev_post(writev, -1, ERROR_OPERATION_ABORTED);
	} else if (writev->bufcnt <= 0) {
#if !LELY_NO_THREADS
		LeaveCriticalSection(&impl->CriticalSection);
#endif
		io_stream_writev_post(writev, -1, ERROR_INVALID_PARAMETER);
	} else {
		int post_writev = !impl->writev_posted
				&& sllist_empty(&impl->writev_queue);
		sllist_push_back(&impl->writev_queue, &task->_node);
		if (post_writev)
			impl->writev_posted = 1;
#if !LELY_NO_THREADS
		LeaveCriticalSection(&impl->CriticalSection);
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
	(void)serial;

	SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
	return -1;
}

static int
io_serial_impl_flush(io_serial_t *serial)
{
	return FlushFileBuffers(io_serial_get_handle(serial)) ? 0 : -1;
}

static int
io_serial_impl_purge(io_serial_t *serial, int how)
{
	DWORD dwFlags;
	switch (how) {
	case IO_SERIAL_PURGE_RX: dwFlags = PURGE_RXCLEAR; break;
	case IO_SERIAL_PURGE_TX: dwFlags = PURGE_TXCLEAR; break;
	case IO_SERIAL_PURGE_RXTX:
		dwFlags = PURGE_RXCLEAR | PURGE_TXCLEAR;
		break;
	default: SetLastError(ERROR_INVALID_PARAMETER); return -1;
	}

	return PurgeComm(io_serial_get_handle(serial), dwFlags) ? 0 : -1;
}

static int
io_serial_impl_get_baud_rate(const io_serial_t *serial)
{
	const struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	EnterCriticalSection((LPCRITICAL_SECTION)&impl->CriticalSection);
#endif
	DCB DCB = impl->DCB;
#if !LELY_NO_THREADS
	LeaveCriticalSection((LPCRITICAL_SECTION)&impl->CriticalSection);
#endif

	return DCB.BaudRate;
}

static int
io_serial_impl_set_baud_rate(io_serial_t *serial, int optval)
{
	struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	EnterCriticalSection(&impl->CriticalSection);
#endif
	DCB DCB = impl->DCB;

	DCB.BaudRate = optval;

	if (!SetCommState(impl->hFile, &DCB)) {
#if !LELY_NO_THREADS
		LeaveCriticalSection(&impl->CriticalSection);
#endif
		return -1;
	}

	impl->DCB = DCB;
#if !LELY_NO_THREADS
	LeaveCriticalSection(&impl->CriticalSection);
#endif

	return 0;
}

static int
io_serial_impl_get_flow_ctrl(const io_serial_t *serial)
{
	const struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	EnterCriticalSection((LPCRITICAL_SECTION)&impl->CriticalSection);
#endif
	DCB DCB = impl->DCB;
#if !LELY_NO_THREADS
	LeaveCriticalSection((LPCRITICAL_SECTION)&impl->CriticalSection);
#endif

	if (DCB.fOutX && DCB.fInX)
		return IO_SERIAL_FLOW_CTRL_SW;
	if (DCB.fOutxCtsFlow && DCB.fRtsControl == RTS_CONTROL_HANDSHAKE)
		return IO_SERIAL_FLOW_CTRL_HW;
	return IO_SERIAL_FLOW_CTRL_NONE;
}

static int
io_serial_impl_set_flow_ctrl(io_serial_t *serial, int optval)
{
	struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	EnterCriticalSection(&impl->CriticalSection);
#endif
	DCB DCB = impl->DCB;

	DCB.fOutxCtsFlow = FALSE;
	DCB.fOutxDsrFlow = FALSE;
	DCB.fDtrControl = DTR_CONTROL_ENABLE;
	DCB.fDsrSensitivity = FALSE;
	DCB.fTXContinueOnXoff = TRUE;
	DCB.fOutX = FALSE;
	DCB.fInX = FALSE;
	DCB.fRtsControl = RTS_CONTROL_ENABLE;

	switch (optval) {
	case IO_SERIAL_FLOW_CTRL_NONE: break;
	case IO_SERIAL_FLOW_CTRL_SW:
		DCB.fOutX = TRUE;
		DCB.fInX = TRUE;
		break;
	case IO_SERIAL_FLOW_CTRL_HW:
		DCB.fOutxCtsFlow = TRUE;
		DCB.fRtsControl = RTS_CONTROL_HANDSHAKE;
		break;
	default:
#if !LELY_NO_THREADS
		LeaveCriticalSection(&impl->CriticalSection);
#endif
		SetLastError(ERROR_INVALID_PARAMETER);
		return -1;
	}

	if (!SetCommState(impl->hFile, &DCB)) {
#if !LELY_NO_THREADS
		LeaveCriticalSection(&impl->CriticalSection);
#endif
		return -1;
	}

	impl->DCB = DCB;
#if !LELY_NO_THREADS
	LeaveCriticalSection(&impl->CriticalSection);
#endif

	return 0;
}

static int
io_serial_impl_get_parity(const io_serial_t *serial)
{
	const struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	EnterCriticalSection((LPCRITICAL_SECTION)&impl->CriticalSection);
#endif
	DCB DCB = impl->DCB;
#if !LELY_NO_THREADS
	LeaveCriticalSection((LPCRITICAL_SECTION)&impl->CriticalSection);
#endif

	if (DCB.fParity) {
		if (DCB.Parity == ODDPARITY)
			return IO_SERIAL_PARITY_ODD;
		if (DCB.Parity == EVENPARITY)
			return IO_SERIAL_PARITY_EVEN;
	}
	return IO_SERIAL_PARITY_NONE;
}

static int
io_serial_impl_set_parity(io_serial_t *serial, int optval)
{
	struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	EnterCriticalSection(&impl->CriticalSection);
#endif
	DCB DCB = impl->DCB;

	switch (optval) {
	case IO_SERIAL_PARITY_NONE:
		DCB.fParity = FALSE;
		DCB.Parity = NOPARITY;
		break;
	case IO_SERIAL_PARITY_ODD:
		DCB.fParity = FALSE;
		DCB.Parity = ODDPARITY;
		break;
	case IO_SERIAL_PARITY_EVEN:
		DCB.fParity = FALSE;
		DCB.Parity = EVENPARITY;
		break;
	default:
#if !LELY_NO_THREADS
		LeaveCriticalSection(&impl->CriticalSection);
#endif
		SetLastError(ERROR_INVALID_PARAMETER);
		return -1;
	}

	if (!SetCommState(impl->hFile, &DCB)) {
#if !LELY_NO_THREADS
		LeaveCriticalSection(&impl->CriticalSection);
#endif
		return -1;
	}

	impl->DCB = DCB;
#if !LELY_NO_THREADS
	LeaveCriticalSection(&impl->CriticalSection);
#endif

	return 0;
}

static int
io_serial_impl_get_stop_bits(const io_serial_t *serial)
{
	const struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	EnterCriticalSection((LPCRITICAL_SECTION)&impl->CriticalSection);
#endif
	DCB DCB = impl->DCB;
#if !LELY_NO_THREADS
	LeaveCriticalSection((LPCRITICAL_SECTION)&impl->CriticalSection);
#endif

	if (DCB.StopBits == TWOSTOPBITS)
		return IO_SERIAL_STOP_BITS_TWO;
	if (DCB.StopBits == ONE5STOPBITS)
		return IO_SERIAL_STOP_BITS_ONE_FIVE;
	return IO_SERIAL_STOP_BITS_ONE;
}

static int
io_serial_impl_set_stop_bits(io_serial_t *serial, int optval)
{
	struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	EnterCriticalSection(&impl->CriticalSection);
#endif
	DCB DCB = impl->DCB;

	switch (optval) {
	case IO_SERIAL_STOP_BITS_ONE: DCB.StopBits = ONESTOPBIT; break;
	case IO_SERIAL_STOP_BITS_ONE_FIVE: DCB.StopBits = ONE5STOPBITS; break;
	case IO_SERIAL_STOP_BITS_TWO: DCB.StopBits = TWOSTOPBITS; break;
	default:
#if !LELY_NO_THREADS
		LeaveCriticalSection(&impl->CriticalSection);
#endif
		SetLastError(ERROR_INVALID_PARAMETER);
		return -1;
	}

	if (!SetCommState(impl->hFile, &DCB)) {
#if !LELY_NO_THREADS
		LeaveCriticalSection(&impl->CriticalSection);
#endif
		return -1;
	}

	impl->DCB = DCB;
#if !LELY_NO_THREADS
	LeaveCriticalSection(&impl->CriticalSection);
#endif

	return 0;
}

static int
io_serial_impl_get_char_size(const io_serial_t *serial)
{
	const struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	EnterCriticalSection((LPCRITICAL_SECTION)&impl->CriticalSection);
#endif
	DCB DCB = impl->DCB;
#if !LELY_NO_THREADS
	LeaveCriticalSection((LPCRITICAL_SECTION)&impl->CriticalSection);
#endif

	return DCB.ByteSize;
}

static int
io_serial_impl_set_char_size(io_serial_t *serial, int optval)
{
	struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	EnterCriticalSection(&impl->CriticalSection);
#endif
	DCB DCB = impl->DCB;

	DCB.ByteSize = optval;

	if (!SetCommState(impl->hFile, &DCB)) {
#if !LELY_NO_THREADS
		LeaveCriticalSection(&impl->CriticalSection);
#endif
		return -1;
	}

	impl->DCB = DCB;
#if !LELY_NO_THREADS
	LeaveCriticalSection(&impl->CriticalSection);
#endif

	return 0;
}

static int
io_serial_impl_get_rx_timeout(const io_serial_t *serial)
{
	const struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	EnterCriticalSection((LPCRITICAL_SECTION)&impl->CriticalSection);
#endif
	COMMTIMEOUTS CommTimeouts = impl->CommTimeouts;
#if !LELY_NO_THREADS
	LeaveCriticalSection((LPCRITICAL_SECTION)&impl->CriticalSection);
#endif

	if (!CommTimeouts.ReadTotalTimeoutMultiplier
			&& !CommTimeouts.ReadTotalTimeoutConstant)
		return CommTimeouts.ReadIntervalTimeout < MAXDWORD ? -1 : 0;
	return CommTimeouts.ReadTotalTimeoutConstant;
}

static int
io_serial_impl_set_rx_timeout(io_serial_t *serial, int optval)
{
	struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	EnterCriticalSection(&impl->CriticalSection);
#endif
	COMMTIMEOUTS CommTimeouts = impl->CommTimeouts;

	if (optval < 0) {
		CommTimeouts.ReadIntervalTimeout = 1;
		CommTimeouts.ReadTotalTimeoutMultiplier = 0;
		CommTimeouts.ReadTotalTimeoutConstant = 0;
	} else if (!optval) {
		CommTimeouts.ReadIntervalTimeout = MAXDWORD;
		CommTimeouts.ReadTotalTimeoutMultiplier = 0;
		CommTimeouts.ReadTotalTimeoutConstant = 0;
	} else {
		CommTimeouts.ReadIntervalTimeout = MAXDWORD;
		CommTimeouts.ReadTotalTimeoutMultiplier = MAXDWORD;
		CommTimeouts.ReadTotalTimeoutConstant =
				MIN((DWORD)optval, MAXDWORD - 1);
	}

	if (!SetCommTimeouts(impl->hFile, &CommTimeouts)) {
#if !LELY_NO_THREADS
		LeaveCriticalSection(&impl->CriticalSection);
#endif
		return -1;
	}

	impl->CommTimeouts = CommTimeouts;
#if !LELY_NO_THREADS
	LeaveCriticalSection(&impl->CriticalSection);
#endif

	return 0;
}

static int
io_serial_impl_get_tx_timeout(const io_serial_t *serial)
{
	const struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	EnterCriticalSection((LPCRITICAL_SECTION)&impl->CriticalSection);
#endif
	COMMTIMEOUTS CommTimeouts = impl->CommTimeouts;
#if !LELY_NO_THREADS
	LeaveCriticalSection((LPCRITICAL_SECTION)&impl->CriticalSection);
#endif

	if (!CommTimeouts.WriteTotalTimeoutMultiplier
			&& !CommTimeouts.WriteTotalTimeoutConstant)
		return -1;
	return CommTimeouts.WriteTotalTimeoutConstant;
}

static int
io_serial_impl_set_tx_timeout(io_serial_t *serial, int optval)
{
	struct io_serial_impl *impl = io_serial_impl_from_serial(serial);

#if !LELY_NO_THREADS
	EnterCriticalSection(&impl->CriticalSection);
#endif
	COMMTIMEOUTS CommTimeouts = impl->CommTimeouts;

	CommTimeouts.WriteTotalTimeoutMultiplier = 0;
	if (optval < 0)
		CommTimeouts.WriteTotalTimeoutConstant = 0;
	else
		CommTimeouts.WriteTotalTimeoutConstant =
				MIN((DWORD)MAX(optval, 1), MAXDWORD);

	if (!SetCommTimeouts(impl->hFile, &CommTimeouts)) {
#if !LELY_NO_THREADS
		LeaveCriticalSection(&impl->CriticalSection);
#endif
		return -1;
	}

	impl->CommTimeouts = CommTimeouts;
#if !LELY_NO_THREADS
	LeaveCriticalSection(&impl->CriticalSection);
#endif

	return 0;
}

static void
io_serial_impl_svc_shutdown(struct io_svc *svc)
{
	struct io_serial_impl *impl = io_serial_impl_from_svc(svc);
	io_dev_t *dev = &impl->dev_vptr;

#if !LELY_NO_THREADS
	EnterCriticalSection(&impl->CriticalSection);
#endif
	int shutdown = !impl->shutdown;
	impl->shutdown = 1;
	if (shutdown)
		// Try to abort io_serial_impl_readv_task_func() and
		// io_serial_impl_writev_task_func().
		io_serial_impl_do_abort_tasks(impl);
#if !LELY_NO_THREADS
	LeaveCriticalSection(&impl->CriticalSection);
#endif

	if (shutdown)
		// Cancel all pending operations.
		io_serial_impl_dev_cancel(dev, NULL);
}

static void
io_serial_impl_readv_task_func(struct ev_task *task)
{
	assert(task);
	struct io_serial_impl *impl =
			structof(task, struct io_serial_impl, readv_task);

	DWORD dwErrCode = GetLastError();

#if !LELY_NO_THREADS
	EnterCriticalSection(&impl->CriticalSection);
#endif
	// Try to process all pending read operations at once, unless we're in
	// blocking mode.
	while ((task = ev_task_from_node(
				sllist_pop_front(&impl->readv_queue)))) {
		struct io_stream_readv *readv = io_stream_readv_from_task(task);
		HANDLE hFile = impl->hFile;
		if ((task->_data = impl->async ? impl : NULL)) {
			// Move the task to the I/O completion port queue.
			sllist_push_back(&impl->readv_iocp_queue, &task->_node);
#if !LELY_NO_THREADS
			LeaveCriticalSection(&impl->CriticalSection);
#endif
			readv->_handle = hFile;
			readv->_cp = (struct io_cp)IO_CP_INIT(
					&io_serial_impl_readv_cp_func);
			// Initiate the first read operation.
			readv->r.result = -1;
			readv->r.errc = 0;
			if (!io_serial_impl_do_readv(readv, 0, 0)) {
				// Post the completion task if the read failed.
				ev_exec_t *exec = readv->task.exec;
				ev_exec_post(exec, &readv->task);
				ev_exec_on_task_fini(exec);
			}
#if !LELY_NO_THREADS
			EnterCriticalSection(&impl->CriticalSection);
#endif
		} else {
#if !LELY_NO_THREADS
			LeaveCriticalSection(&impl->CriticalSection);
#endif
			ssize_t result = io_serial_fd_readv(
					hFile, readv->buf, readv->bufcnt);
			int errc = result >= 0 ? 0 : GetLastError();
			io_stream_readv_post(readv, result, errc);
#if !LELY_NO_THREADS
			EnterCriticalSection(&impl->CriticalSection);
#endif
			break;
		}
	}
	int post_readv = impl->readv_posted =
			!sllist_empty(&impl->readv_queue) && !impl->shutdown;
#if !LELY_NO_THREADS
	LeaveCriticalSection(&impl->CriticalSection);
#endif

	if (post_readv)
		ev_exec_post(impl->readv_task.exec, &impl->readv_task);

	SetLastError(dwErrCode);
}

static int
io_serial_impl_do_readv(struct io_stream_readv *readv, size_t nbytes, int errc)
{
	assert(readv);
	assert(readv->bufcnt > 0);
	assert(readv->buf);
	HANDLE hFile = readv->_handle;

	int first = readv->r.result < 0;
	if (first)
		readv->r.result = 0;
	assert(!readv->r.errc);
	readv->r.errc = errc;

	// Find the current input buffer.
	int i = 0;
	size_t n = readv->r.result;
	while (n) {
		assert(n >= readv->buf[i].len);
		n -= readv->buf[i++].len;
	}

	assert(nbytes <= ULONG_MAX
			&& readv->r.result <= (ssize_t)(SSIZE_MAX - nbytes));
	readv->r.result += nbytes;
	// We're done if an error occurred, a buffer was partially read (which
	// indicates a timeout) or the last buffer was filled.
	if (errc || (!first && nbytes < readv->buf[i].len)
			|| ++i == readv->bufcnt)
		return 0;

	DWORD dwErrCode = GetLastError();
	// clang-format off
	if (!ReadFile(hFile, readv->buf[i].base, readv->buf[i].len, NULL,
			&readv->_cp.overlapped)) {
		// clang-format on
		if (GetLastError() != ERROR_IO_PENDING) {
			readv->r.errc = GetLastError();
			return 0;
		}
		SetLastError(dwErrCode);
	}

	return 1;
}

static void
io_serial_impl_readv_cp_func(struct io_cp *cp, size_t nbytes, int errc)
{
	assert(cp);
	struct io_stream_readv *readv =
			structof(cp, struct io_stream_readv, _cp);
	struct io_serial_impl *impl = readv->task._data;
	assert(impl);

	// Process the result of the previous read operation and initiate the
	// next read, if necessary.
	if (io_serial_impl_do_readv(readv, nbytes, errc))
		return;

	if (errc != ERROR_OPERATION_ABORTED) {
#if !LELY_NO_THREADS
		EnterCriticalSection(&impl->CriticalSection);
#endif
		sllist_remove(&impl->readv_iocp_queue, &readv->task._node);
#if !LELY_NO_THREADS
		LeaveCriticalSection(&impl->CriticalSection);
#endif
	}

	// Only report a negative result if no bytes were read.
	if (!readv->r.result && readv->r.errc)
		readv->r.result = -1;

	ev_exec_t *exec = readv->task.exec;
	ev_exec_post(exec, &readv->task);
	ev_exec_on_task_fini(exec);
}

static void
io_serial_impl_writev_task_func(struct ev_task *task)
{
	assert(task);
	struct io_serial_impl *impl =
			structof(task, struct io_serial_impl, writev_task);

	DWORD dwErrCode = GetLastError();

#if !LELY_NO_THREADS
	EnterCriticalSection(&impl->CriticalSection);
#endif
	// Try to process all pending write operations at once, unless we're in
	// blocking mode.
	while ((task = ev_task_from_node(
				sllist_pop_front(&impl->writev_queue)))) {
		struct io_stream_writev *writev =
				io_stream_writev_from_task(task);
		HANDLE hFile = impl->hFile;
		if ((task->_data = impl->async ? impl : NULL)) {
			// Move the task to the I/O completion port queue.
			sllist_push_back(
					&impl->writev_iocp_queue, &task->_node);
#if !LELY_NO_THREADS
			LeaveCriticalSection(&impl->CriticalSection);
#endif
			writev->_handle = hFile;
			writev->_cp = (struct io_cp)IO_CP_INIT(
					&io_serial_impl_writev_cp_func);
			// Initiate the first write operation.
			writev->r.result = -1;
			writev->r.errc = 0;
			if (!io_serial_impl_do_writev(writev, 0, 0)) {
				// Post the completion task if the write failed.
				ev_exec_t *exec = writev->task.exec;
				ev_exec_post(exec, &writev->task);
				ev_exec_on_task_fini(exec);
			}
#if !LELY_NO_THREADS
			EnterCriticalSection(&impl->CriticalSection);
#endif
		} else {
#if !LELY_NO_THREADS
			LeaveCriticalSection(&impl->CriticalSection);
#endif
			ssize_t result = io_serial_fd_writev(
					hFile, writev->buf, writev->bufcnt);
			int errc = result >= 0 ? 0 : GetLastError();
			io_stream_writev_post(writev, result, errc);
#if !LELY_NO_THREADS
			EnterCriticalSection(&impl->CriticalSection);
#endif
			break;
		}
	}
	int post_writev = impl->writev_posted =
			!sllist_empty(&impl->writev_queue) && !impl->shutdown;
#if !LELY_NO_THREADS
	LeaveCriticalSection(&impl->CriticalSection);
#endif

	if (post_writev)
		ev_exec_post(impl->writev_task.exec, &impl->writev_task);

	SetLastError(dwErrCode);
}

static int
io_serial_impl_do_writev(
		struct io_stream_writev *writev, size_t nbytes, int errc)
{
	assert(writev);
	assert(writev->bufcnt > 0);
	assert(writev->buf);
	HANDLE hFile = writev->_handle;

	int first = writev->r.result < 0;
	if (first)
		writev->r.result = 0;
	assert(!writev->r.errc);
	writev->r.errc = errc;

	// Find the current output buffer.
	int i = 0;
	size_t n = writev->r.result;
	while (n) {
		assert(n >= writev->buf[i].len);
		n -= writev->buf[i++].len;
	}

	assert(nbytes <= ULONG_MAX
			&& writev->r.result <= (ssize_t)(SSIZE_MAX - nbytes));
	writev->r.result += nbytes;
	// We're done if an error occurred, a buffer was partially written
	// (which indicates a timeout) or the last buffer was written.
	if (errc || (!first && nbytes < writev->buf[i].len)
			|| ++i == writev->bufcnt)
		return 0;

	DWORD dwErrCode = GetLastError();
	// clang-format off
	if (!WriteFile(hFile, writev->buf[i].base, writev->buf[i].len, NULL,
			&writev->_cp.overlapped)) {
		// clang-format on
		if (GetLastError() != ERROR_IO_PENDING) {
			writev->r.errc = GetLastError();
			return 0;
		}
		SetLastError(dwErrCode);
	}

	return 1;
}

static void
io_serial_impl_writev_cp_func(struct io_cp *cp, size_t nbytes, int errc)
{
	assert(cp);
	struct io_stream_writev *writev =
			structof(cp, struct io_stream_writev, _cp);
	struct io_serial_impl *impl = writev->task._data;
	assert(impl);

	// Process the result of the previous write operation and initiate the
	// next write, if necessary.
	if (io_serial_impl_do_writev(writev, nbytes, errc))
		return;

	if (errc != ERROR_OPERATION_ABORTED) {
#if !LELY_NO_THREADS
		EnterCriticalSection(&impl->CriticalSection);
#endif
		sllist_remove(&impl->writev_iocp_queue, &writev->task._node);
#if !LELY_NO_THREADS
		LeaveCriticalSection(&impl->CriticalSection);
#endif
	}

	// Only report a negative result if no bytes were write.
	if (!writev->r.result && writev->r.errc)
		writev->r.result = -1;

	ev_exec_t *exec = writev->task.exec;
	ev_exec_post(exec, &writev->task);
	ev_exec_on_task_fini(exec);
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

static size_t
io_serial_impl_do_cancel_iocp(struct io_serial_impl *impl, struct ev_task *task)
{
	assert(impl);

	size_t n = 0;
	DWORD dwErrCode = GetLastError();

	// Try to cancel matching read operations waiting for a completion
	// packet.
	for (struct slnode **pnode = &impl->readv_iocp_queue.first; *pnode;
			pnode = &(*pnode)->next) {
		struct io_stream_readv *readv = io_stream_readv_from_task(
				ev_task_from_node(*pnode));
		if (task && task != &readv->task)
			continue;
		if (!CancelIoEx((HANDLE)readv->_handle, &readv->_cp.overlapped))
			continue;
		n += n < SIZE_MAX;
		// Remove the task from the queue.
		if (!(*pnode = (*pnode)->next)) {
			impl->readv_iocp_queue.plast = pnode;
			break;
		}
	}

	// Try to cancel matching write operations waiting for a completion
	// packet.
	for (struct slnode **pnode = &impl->writev_iocp_queue.first; *pnode;
			pnode = &(*pnode)->next) {
		struct io_stream_writev *writev = io_stream_writev_from_task(
				ev_task_from_node(*pnode));
		if (task && task != &writev->task)
			continue;
		if (!CancelIoEx((HANDLE)writev->_handle,
				    &writev->_cp.overlapped))
			continue;
		n += n < SIZE_MAX;
		// Remove the task from the queue.
		if (!(*pnode = (*pnode)->next)) {
			impl->writev_iocp_queue.plast = pnode;
			break;
		}
	}

	SetLastError(dwErrCode);
	return n;
}

static HANDLE
io_serial_impl_set_handle(struct io_serial_impl *impl, HANDLE hFile,
		LPDCB lpDCB, BOOL bAsync)
{
	assert(impl);

	struct sllist readv_queue, writev_queue;
	sllist_init(&readv_queue);
	sllist_init(&writev_queue);

#if !LELY_NO_THREADS
	EnterCriticalSection(&impl->CriticalSection);
#endif

	HANDLE tmp = impl->hFile;
	impl->hFile = hFile;
	hFile = tmp;

	impl->DCB = lpDCB ? *lpDCB : (DCB){ .DCBlength = sizeof(DCB) };
	io_serial_impl_set_timeouts(impl, &impl->CommTimeouts);

	impl->async = impl->poll && bAsync;

	// Cancel pending operations.
	sllist_append(&readv_queue, &impl->readv_queue);
	sllist_append(&writev_queue, &impl->writev_queue);

	// Cancel operations waiting for a completion packet.
	io_serial_impl_do_cancel_iocp(impl, NULL);

#if !LELY_NO_THREADS
	LeaveCriticalSection(&impl->CriticalSection);
#endif

	io_stream_readv_queue_post(&readv_queue, -1, ECANCELED);
	io_stream_writev_queue_post(&writev_queue, -1, ECANCELED);

	return hFile;
}

static void
io_serial_impl_set_timeouts(const struct io_serial_impl *impl,
		LPCOMMTIMEOUTS lpCommTimeouts)
{
	assert(impl);
	assert(lpCommTimeouts);

	*lpCommTimeouts = (COMMTIMEOUTS){ .ReadIntervalTimeout = 1 };
	if (!impl->async) {
		lpCommTimeouts->ReadIntervalTimeout = MAXDWORD;
		lpCommTimeouts->ReadTotalTimeoutMultiplier = MAXDWORD;
		lpCommTimeouts->ReadTotalTimeoutConstant = LELY_IO_RX_TIMEOUT;
		lpCommTimeouts->WriteTotalTimeoutConstant = LELY_IO_TX_TIMEOUT;
	}
}

#endif // _WIN32
