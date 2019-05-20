/**@file
 * This file is part of the I/O library; it contains the I/O polling
 * implementation for Windows.
 *
 * @see lely/io2/win32/afd.h
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

#include <lely/io2/win32/afd.h>

#include <assert.h>
#include <limits.h>

static PCWSTR wszAfdDeviceName = L"\\Device\\Afd";

HANDLE
AfdOpen(DWORD dwFlags)
{
	assert(lpfnNtCreateFile);
	assert(lpfnRtlInitUnicodeString);
	assert(lpfnRtlNtStatusToDosError);

	if (dwFlags & ~FILE_FLAG_OVERLAPPED) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return INVALID_HANDLE_VALUE;
	}

	HANDLE hAfdDevice = INVALID_HANDLE_VALUE;
	UNICODE_STRING ObjectName;
	lpfnRtlInitUnicodeString(&ObjectName, wszAfdDeviceName);
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(
			&ObjectAttributes, &ObjectName, 0, NULL, NULL);

	IO_STATUS_BLOCK IoStatusBlock;

	ULONG CreateOptions = 0;
	if (!(dwFlags & FILE_FLAG_OVERLAPPED))
		CreateOptions |= FILE_SYNCHRONOUS_IO_NONALERT;

	NTSTATUS Status = lpfnNtCreateFile(&hAfdDevice, SYNCHRONIZE,
			&ObjectAttributes, &IoStatusBlock, NULL, 0,
			FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
			CreateOptions, NULL, 0);
	if (!NT_SUCCESS(Status)) {
		SetLastError(lpfnRtlNtStatusToDosError(Status));
		return INVALID_HANDLE_VALUE;
	}

	return hAfdDevice;
}

BOOL
AfdPoll(HANDLE hAfdDevice, PAFD_POLL_INFO lpPollInfoIn,
		PAFD_POLL_INFO lpPollInfoOut, LPDWORD lpNumberOfHandles,
		LPOVERLAPPED lpOverlapped)
{
	DWORD nInBufferSize = 0;
	if (lpPollInfoIn) {
		nInBufferSize = AFD_POLL_INFO_SIZE;
		nInBufferSize += lpPollInfoIn->NumberOfHandles
				* sizeof(AFD_POLL_HANDLE_INFO);
	}

	DWORD nOutBufferSize = 0;
	if (lpPollInfoOut) {
		nOutBufferSize = AFD_POLL_INFO_SIZE;
		nOutBufferSize += lpPollInfoOut->NumberOfHandles
				* sizeof(AFD_POLL_HANDLE_INFO);
	}

	if (lpNumberOfHandles)
		*lpNumberOfHandles = 0;

	DWORD dwBytesReturned = 0;
	// clang-format off
	if (!DeviceIoControl(hAfdDevice, IOCTL_AFD_POLL, lpPollInfoIn,
		nInBufferSize, lpPollInfoOut, nOutBufferSize,
		&dwBytesReturned, lpOverlapped))
		// clang-format on
		return FALSE;

	if (lpNumberOfHandles && dwBytesReturned >= AFD_POLL_INFO_SIZE) {
		dwBytesReturned -= AFD_POLL_INFO_SIZE;
		*lpNumberOfHandles =
				dwBytesReturned / sizeof(AFD_POLL_HANDLE_INFO);
	}

	return TRUE;
}

BOOL
AfdPollWait(HANDLE hAfdDevice, PAFD_POLL_HANDLE_INFO lpPollHandleInfo,
		LPDWORD lpNumberOfHandles, DWORD dwMilliseconds)
{
	if (!lpNumberOfHandles || (*lpNumberOfHandles && !lpPollHandleInfo)) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	HANDLE hEvent = io_win32_tls_get_event();
	if (!hEvent)
		return FALSE;
	// Prevent the I/O completion from being queued to the I/O completion
	// port.
	OVERLAPPED Overlapped = { .hEvent = (HANDLE)((UINT_PTR)hEvent | 1) };

	// Only use the heap in case of more than one handle.
	AFD_POLL_INFO PollInfo = { .NumberOfHandles = 0 };
	PAFD_POLL_INFO lpPollInfo = &PollInfo;
	if (*lpNumberOfHandles > 1) {
		SIZE_T uBytes = AFD_POLL_INFO_SIZE;
		uBytes += *lpNumberOfHandles * sizeof(AFD_POLL_HANDLE_INFO);
		lpPollInfo = LocalAlloc(LPTR, uBytes);
		if (!lpPollInfo)
			return FALSE;
	}

	BaseFormatTimeOut(&lpPollInfo->Timeout, dwMilliseconds);
	lpPollInfo->NumberOfHandles = *lpNumberOfHandles;
	lpPollInfo->Exclusive = FALSE;
	for (DWORD i = 0; i < lpPollInfo->NumberOfHandles; i++)
		lpPollInfo->Handles[i] = lpPollHandleInfo[i];

	BOOL fSuccess = FALSE;
	DWORD dwErrCode = GetLastError();

	if (!AfdPoll(hAfdDevice, lpPollInfo, lpPollInfo, NULL, &Overlapped)) {
		if (GetLastError() != ERROR_IO_PENDING) {
			dwErrCode = GetLastError();
			goto error;
		}
		SetLastError(dwErrCode);
		if (!GetOverlappedResult(hAfdDevice, &Overlapped, NULL, TRUE)) {
			dwErrCode = GetLastError();
			goto error;
		}
	}

	for (DWORD i = 0; i < lpPollInfo->NumberOfHandles; i++)
		lpPollHandleInfo[i] = lpPollInfo->Handles[i];
	*lpNumberOfHandles = lpPollInfo->NumberOfHandles;

	fSuccess = TRUE;

error:
	if (lpPollInfo != &PollInfo)
		LocalFree(lpPollInfo);
	SetLastError(dwErrCode);
	return fSuccess;
}

PLARGE_INTEGER
BaseFormatTimeOut(PLARGE_INTEGER Timeout, DWORD dwMilliseconds)
{
	if (dwMilliseconds == INFINITE) {
		if (Timeout)
			Timeout->QuadPart = LLONG_MAX;
		return NULL;
	} else if (Timeout) {
		// A relative timeout is specified as a negative number of
		// 100-nanosecond units.
		Timeout->QuadPart = UInt32x32To64(dwMilliseconds, -10000);
	}
	return Timeout;
}

ULONG
NtStatusToDosError(LONG Status)
{
	assert(lpfnRtlNtStatusToDosError);

	return lpfnRtlNtStatusToDosError(Status);
}

#endif // _WIN32
