/**@file
 * This header file is part of the I/O library; it contains the interface for
 * the polling functionality of the Ancillary Function Driver (AFD).
 *
 * See <a href="https://github.com/piscisaureus/wepoll">wepoll</a> for more
 * information about AFD.
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

#ifndef LELY_IO2_WIN32_AFD_H_
#define LELY_IO2_WIN32_AFD_H_

#include <lely/features.h>

#include <stddef.h>

#include <windows.h>

#define IOCTL_AFD_POLL 0x00012024

#define AFD_POLL_RECEIVE (1u << 0)
#define AFD_POLL_RECEIVE_EXPEDITED (1u << 1)
#define AFD_POLL_SEND (1u << 2)
#define AFD_POLL_DISCONNECT (1u << 3)
#define AFD_POLL_ABORT (1u << 4)
#define AFD_POLL_LOCAL_CLOSE (1u << 5)
#define AFD_POLL_CONNECT (1u << 6)
#define AFD_POLL_ACCEPT (1u << 7)
#define AFD_POLL_CONNECT_FAIL (1u << 8)
#define AFD_POLL_QOS (1u << 9)
#define AFD_POLL_GROUP_QOS (1u << 10)

typedef struct {
	HANDLE Handle;
	ULONG Events;
	LONG Status;
} AFD_POLL_HANDLE_INFO, *PAFD_POLL_HANDLE_INFO;

typedef struct {
	LARGE_INTEGER Timeout;
	ULONG NumberOfHandles;
	ULONG Exclusive;
	AFD_POLL_HANDLE_INFO Handles[1];
} AFD_POLL_INFO, *PAFD_POLL_INFO;

#define AFD_POLL_INFO_SIZE (offsetof(AFD_POLL_INFO, Handles))

#ifdef __cplusplus
extern "C" {
#endif

HANDLE AfdOpen(DWORD dwFlags);

BOOL AfdPoll(HANDLE hAfdDevice, PAFD_POLL_INFO lpPollInfoIn,
		PAFD_POLL_INFO lpPollInfoOut, LPDWORD lpNumberOfHandles,
		LPOVERLAPPED lpOverlapped);

BOOL AfdPollWait(HANDLE hAfdDevice, PAFD_POLL_HANDLE_INFO lpPollHandleInfo,
		LPDWORD lpNumberOfHandles, DWORD dwMilliseconds);

PLARGE_INTEGER BaseFormatTimeOut(PLARGE_INTEGER Timeout, DWORD dwMilliseconds);

ULONG NtStatusToDosError(LONG Status);

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_WIN32_AFD_H_
