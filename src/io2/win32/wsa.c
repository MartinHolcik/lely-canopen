/**@file
 * This file is part of the I/O library; it contains the implementation of the
 * Windows Sockets API (WSA) functions.
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

#include "wsa.h"

#if _WIN32

#include <assert.h>

static int io_wsa_poll(SOCKET s, int *events, int timeout);

int
io_win32_wsa_init(void)
{
	int iError = 0;

	WSADATA WSAData;
	if ((iError = WSAStartup(MAKEWORD(2, 2), &WSAData)))
		goto error_WSAStartup;

	if (LOBYTE(WSAData.wVersion) != 2 || HIBYTE(WSAData.wVersion) != 2) {
		iError = WSAVERNOTSUPPORTED;
		goto error_WSAData;
	}

	return 0;

error_WSAData:
	WSACleanup();
error_WSAStartup:
	WSASetLastError(iError);
	return -1;
}

void
io_win32_wsa_fini(void)
{
	WSACleanup();
}

LPFN_ACCEPTEX
io_wsa_get_acceptex(SOCKET s)
{
	LPFN_ACCEPTEX lpfnAcceptEx = NULL;
	DWORD lpcbBytesReturned = 0;
	// clang-format off
	if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER,
			&(GUID)WSAID_ACCEPTEX, sizeof(GUID), &lpfnAcceptEx,
			sizeof(LPFN_ACCEPTEX), &lpcbBytesReturned, NULL, NULL)
			== SOCKET_ERROR)
		// clang-format on
		return NULL;
	return lpfnAcceptEx;
}

LPFN_CONNECTEX
io_wsa_get_connectex(SOCKET s)
{
	LPFN_CONNECTEX lpfnConnectEx = NULL;
	DWORD lpcbBytesReturned = 0;
	// clang-format off
	if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER,
			&(GUID)WSAID_CONNECTEX, sizeof(GUID), &lpfnConnectEx,
			sizeof(LPFN_CONNECTEX), &lpcbBytesReturned, NULL, NULL)
			== SOCKET_ERROR)
		// clang-format on
		return NULL;
	return lpfnConnectEx;
}

int
io_wsa_set_nonblock(SOCKET s)
{
	return !ioctlsocket(s, FIONBIO, &(u_long){ 1 }) ? 0 : -1;
}

int
io_wsa_wait(SOCKET s, int *events, int timeout)
{
	assert(events);

	// WSAPoll() does not report failed connection attempts, so we cannot
	// use it to monitor POLLOUT when a connection attempt is in progress.
	if (!(*events & POLLOUT))
		return io_wsa_poll(s, events, timeout);

	int type;
	// clang-format off
	if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&type,
			&(int){ sizeof(int) }) == SOCKET_ERROR)
		// clang-format on
		return -1;
	// Connectionless sockets do not suffer from the WSAPoll() bug.
	if (type != SOCK_STREAM && type != SOCK_SEQPACKET)
		return io_wsa_poll(s, events, timeout);

	int result = -1;
	int iError = WSAGetLastError();

	struct sockaddr_storage name = { .ss_family = AF_UNSPEC };
	int namelen = sizeof(name);
	// It is safe to call WSAPoll() on connected sockets.
	if (!getpeername(s, (struct sockaddr *)&name, &namelen))
		return io_wsa_poll(s, events, timeout);
	if (WSAGetLastError() != WSAENOTCONN)
		return -1;

	long lNetworkEvents = FD_CLOSE;
	if (*events & POLLRDNORM)
		lNetworkEvents |= FD_READ | FD_ACCEPT;
	if (*events & POLLRDBAND)
		lNetworkEvents |= FD_OOB;
	if (*events & POLLOUT)
		lNetworkEvents |= FD_WRITE | FD_CONNECT;
	*events = 0;

	WSAEVENT hEventObject = WSACreateEvent();
	if (hEventObject == WSA_INVALID_EVENT) {
		iError = WSAGetLastError();
		goto error_WSACreateEvent;
	}

	if (WSAEventSelect(s, hEventObject, lNetworkEvents) == SOCKET_ERROR) {
		iError = WSAGetLastError();
		goto error_WSAEventSelect;
	}

	DWORD dwTimeout = timeout >= 0 ? (DWORD)timeout : WSA_INFINITE;
	BOOL fAlertable = timeout >= 0 ? FALSE : TRUE;
	do {
		DWORD dwWaitResult = WSAWaitForMultipleEvents(
				1, &hEventObject, FALSE, dwTimeout, fAlertable);
		if (dwWaitResult == WSA_WAIT_IO_COMPLETION)
			continue;
		fAlertable = FALSE;
		if (dwWaitResult != WSA_WAIT_EVENT_0) {
			iError = GetLastError();
			goto error_WSAWaitForMultipleEvents;
		}
	} while (fAlertable);

	WSANETWORKEVENTS NetworkEvents = { .lNetworkEvents = 0 };
	if (WSAEnumNetworkEvents(s, hEventObject, &NetworkEvents)
			== SOCKET_ERROR) {
		iError = WSAGetLastError();
		goto error_WSAEnumNetworkEvents;
	}

	lNetworkEvents = NetworkEvents.lNetworkEvents;
	if (lNetworkEvents & (FD_READ | FD_ACCEPT))
		*events |= POLLRDNORM;
	if (lNetworkEvents & FD_OOB)
		*events |= POLLRDBAND | POLLPRI;
	if (lNetworkEvents & (FD_WRITE | FD_CONNECT))
		*events |= POLLOUT;
	if (lNetworkEvents & FD_CLOSE)
		*events |= POLLHUP;

	result = 0;

error_WSAEnumNetworkEvents:
error_WSAWaitForMultipleEvents:
	WSAEventSelect(s, hEventObject, 0);
error_WSAEventSelect:
	WSACloseEvent(hEventObject);
error_WSACreateEvent:
	WSASetLastError(iError);
	return result;
}

SOCKET
io_wsa_socket(int af, int type, int protocol)
{
	int iError = 0;

	SOCKET s = WSASocketA(af, type, protocol, NULL, 0,
			WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
	if (s == INVALID_SOCKET) {
		iError = WSAGetLastError();
		goto error_WSASocketA;
	}

	if (io_wsa_set_nonblock(s) == -1) {
		iError = WSAGetLastError();
		goto error_set_nonblock;
	}

	return s;

error_set_nonblock:
	closesocket(s);
error_WSASocketA:
	WSASetLastError(iError);
	return INVALID_SOCKET;
}

SOCKET
io_wsa_accept(SOCKET s, SOCKADDR *addr, int *addrlen, int timeout)
{
	SOCKET sAcceptSocket = INVALID_SOCKET;
	int iError = WSAGetLastError();
	for (;;) {
		// Try to accept a pending connection.
		sAcceptSocket = accept(s, addr, addrlen);
		if (sAcceptSocket != INVALID_SOCKET)
			break;
		if (!timeout || WSAGetLastError() != WSAEWOULDBLOCK)
			return INVALID_SOCKET;
		// Wait for an incoming connection.
		int events = POLLRDNORM;
		if (io_wsa_poll(s, &events, timeout) == -1)
			return INVALID_SOCKET;
		// Since the timeout is relative, we can only use a positive
		// value once.
		if (timeout > 0)
			timeout = 0;
		WSASetLastError(iError);
	}

	// clang-format off
	if (!SetHandleInformation(
			(HANDLE)sAcceptSocket, HANDLE_FLAG_INHERIT, 0)) {
		// clang-format on
		DWORD dwErrCode = GetLastError();
		closesocket(sAcceptSocket);
		SetLastError(dwErrCode);
		return INVALID_SOCKET;
	}

	return sAcceptSocket;
}

int
io_wsa_connect(SOCKET s, const SOCKADDR *name, int namelen, int dontwait)
{
	int result = -1;
	int iError = WSAGetLastError();

	WSAEVENT hEventObject = WSA_INVALID_EVENT;

	if (!dontwait) {
		hEventObject = WSACreateEvent();
		if (hEventObject == WSA_INVALID_EVENT) {
			iError = WSAGetLastError();
			goto error_WSACreateEvent;
		}

		if (WSAEventSelect(s, hEventObject, FD_CONNECT)
				== SOCKET_ERROR) {
			iError = WSAGetLastError();
			goto error_WSAEventSelect;
		}
	}

	// Try to establish a connection.
	result = !connect(s, name, namelen) ? 0 : -1;
	if (result == -1 && (dontwait || WSAGetLastError() != WSAEWOULDBLOCK)) {
		iError = WSAGetLastError();
		goto error_connect;
	}

	while (result == -1) {
		// The connection is in progress; wait for it to be established.
		DWORD dwWaitResult = WSAWaitForMultipleEvents(
				1, &hEventObject, FALSE, WSA_INFINITE, TRUE);
		if (dwWaitResult == WSA_WAIT_FAILED) {
			iError = GetLastError();
			goto error_WSAWaitForMultipleEvents;
		}
		if (dwWaitResult != WSA_WAIT_EVENT_0)
			continue;

		WSANETWORKEVENTS NetworkEvents = { .lNetworkEvents = 0 };
		if (WSAEnumNetworkEvents(s, hEventObject, &NetworkEvents)
				== SOCKET_ERROR) {
			iError = WSAGetLastError();
			goto error_WSAEnumNetworkEvents;
		}
		// Obtain the result of the connection attempt.
		if (NetworkEvents.lNetworkEvents & FD_CONNECT) {
			// clang-format off
			int iErrorCode = NetworkEvents.iErrorCode[FD_CONNECT_BIT];
			// clang-format on
			if (iErrorCode)
				iError = iErrorCode;
			else
				result = 0;
			break;
		}
	}

error_WSAEnumNetworkEvents:
error_WSAWaitForMultipleEvents:
error_connect:
	if (!dontwait)
		WSAEventSelect(s, hEventObject, 0);
error_WSAEventSelect:
	if (!dontwait)
		WSACloseEvent(hEventObject);
error_WSACreateEvent:
	WSASetLastError(iError);
	return result;
}

ssize_t
io_wsa_recvfrom(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
		LPDWORD lpFlags, SOCKADDR *lpFrom, LPINT lpFromlen, int timeout)
{
	assert(lpFlags);

	int iError = WSAGetLastError();
	for (;;) {
		// Try to receive a message.
		DWORD dwNumberOfBytesRecvd = 0;
		// clang-format off
		if (!WSARecvFrom(s, lpBuffers, dwBufferCount,
				&dwNumberOfBytesRecvd, lpFlags, lpFrom,
				lpFromlen, NULL, NULL))
			// clang-format on
			return dwNumberOfBytesRecvd;
		if (!timeout || WSAGetLastError() != WSAEWOULDBLOCK)
			return -1;
		// Wait for a message to arrive.
		int events = (*lpFlags & MSG_OOB) ? POLLRDBAND : POLLRDNORM;
		if (io_wsa_poll(s, &events, timeout) == -1)
			return -1;
		// Since the timeout is relative, we can only use a positive
		// value once.
		if (timeout > 0)
			timeout = 0;
		WSASetLastError(iError);
	}
}

ssize_t
io_wsa_sendto(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, DWORD dwFlags,
		const SOCKADDR *lpTo, int iTolen, int timeout)
{
	int iError = WSAGetLastError();
	for (;;) {
		// Try to send a message.
		DWORD dwNumberOfBytesSent = 0;
		// clang-format off
		if (!WSASendTo(s, lpBuffers, dwBufferCount,
				&dwNumberOfBytesSent, dwFlags, lpTo, iTolen,
				NULL, NULL))
			// clang-format on
			return dwNumberOfBytesSent;
		if (!timeout || WSAGetLastError() != WSAEWOULDBLOCK)
			return -1;
		// Wait for the socket to become ready.
		int events = POLLOUT;
		if (io_wsa_poll(s, &events, timeout) == -1)
			return -1;
		// Since the timeout is relative, we can only use a positive
		// value once.
		if (timeout > 0)
			timeout = 0;
		WSASetLastError(iError);
	}
}

SOCKET
io_wsa_base_handle(SOCKET s)
{
	int iError = WSAGetLastError();
	DWORD cbBytesReturned = 0;
	// clang-format off
	if (WSAIoctl(s, SIO_BASE_HANDLE, NULL, 0, &s, sizeof(s),
			&cbBytesReturned, NULL, NULL) == SOCKET_ERROR)
		// clang-format on
		// If this operation is not supported (as it is on Wine), the
		// best we can do is ignore the error and return original
		// handle.
		WSASetLastError(iError);
	return s;
}

static int
io_wsa_poll(SOCKET s, int *events, int timeout)
{
	assert(events);

	// WSAPoll() does not support POLLPRI. Out-of-band data is indicated via
	// POLLRDBAND.
	if (*events & POLLPRI) {
		*events &= ~POLLPRI;
		*events |= POLLRDBAND;
	}

	WSAPOLLFD fdArray[1] = { { .fd = s, .events = *events } };
	int result = WSAPoll(fdArray, 1, timeout);
	*events = 0;
	if (result == SOCKET_ERROR)
		return -1;
	if (!result && timeout >= 0) {
		WSASetLastError(WSAEWOULDBLOCK);
		return -1;
	}
	assert(result == 1);
	*events = fdArray[0].revents;

	return 0;
}

#endif // _WIN32
