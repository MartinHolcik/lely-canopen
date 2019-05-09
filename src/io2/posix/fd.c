/**@file
 * This file is part of the I/O library; it contains the implementation of the
 * common file descriptor functions.
 *
 * @copyright 2018-2019 Lely Industries N.V.
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

#include "fd.h"

#if _POSIX_C_SOURCE >= 200112L

#include <assert.h>
#include <errno.h>

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#ifndef LELY_HAVE_ACCEPT4
// TODO: accept4() is also supported by DragonFly 4.3, NetBSD 8.0 and
// OpenBSD 5.7.
#if defined(__linux__) || (__FreeBSD__ >= 10)
#define LELY_HAVE_ACCEPT4 1
#endif
#endif

int
io_fd_set_cloexec(int fd)
{
	int arg = fcntl(fd, F_GETFD);
	if (arg == -1)
		return -1;
	if (!(arg & FD_CLOEXEC) && fcntl(fd, F_SETFD, arg | FD_CLOEXEC) == -1)
		return -1;
	return 0;
}

int
io_fd_set_nonblock(int fd)
{
	int arg = fcntl(fd, F_GETFL);
	if (arg == -1)
		return -1;
	if (!(arg & O_NONBLOCK) && fcntl(fd, F_SETFL, arg | O_NONBLOCK) == -1)
		return -1;
	return 0;
}

int
io_fd_wait(int fd, int *events, int timeout)
{
	assert(events);

	int result;
	struct pollfd fds[1] = { { .fd = fd, .events = *events } };
	do
		result = poll(fds, 1, timeout);
	// clang-format off
	while (result == -1 && ((timeout < 0 && errno == EINTR)
			|| errno == EAGAIN));
	// clang-format on
	*events = 0;
	if (result == -1)
		return -1;
	if (!result && timeout >= 0) {
		errno = EAGAIN;
		return -1;
	}
	assert(result == 1);
	*events = fds[0].revents;
	return 0;
}

int
io_fd_socket(int domain, int type, int protocol)
{
#if defined(SOCK_NONBLOCK) && defined(SOCK_CLOEXEC)
	return socket(domain, type | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
#else
	int errsv = 0;

	int fd = socket(domain, type, protocol);
	if (fd == -1) {
		errsv = errno;
		goto error_socket;
	}

	if (io_fd_set_cloexec(fd) == -1) {
		errsv = errno;
		goto error_set_cloexec;
	}

	if (io_fd_set_nonblock(fd) == -1) {
		errsv = errno;
		goto error_set_nonblock;
	}

error_set_nonblock:
error_set_cloexec:
	close(fd);
error_socket:
	errno = errsv;
	return -1;
#endif
}

int
io_fd_accept(int fd, int flags, struct sockaddr *addr, socklen_t *addrlen,
		int timeout)
{
#if LELY_HAVE_ACCEPT4
	int flags_ = 0;
	if (flags & O_CLOEXEC)
		flags_ |= SOCK_CLOEXEC;
	if (flags & O_NONBLOCK)
		flags_ |= SOCK_NONBLOCK;
#endif

	int result = -1;
	int errsv = errno;
	for (;;) {
		errno = errsv;
		// Try to accept a pending connection.
#if LELY_HAVE_ACCEPT4
		result = accept4(fd, addr, addrlen, flags_);
#else
		result = accept(fd, addr, addrlen);
#endif
		if (result >= 0)
			break;
		if (errno == EINTR)
			continue;
		if (!timeout || (errno != EAGAIN && errno != EWOULDBLOCK))
			return -1;
		// Wait for an incoming connection.
		int events = POLLIN;
		if (io_fd_wait(fd, &events, timeout) == -1)
			return -1;
		// Since the timeout is relative, we can only use a positive
		// value once.
		if (timeout > 0)
			timeout = 0;
	}
#if !LELY_HAVE_ACCEPT4
	if ((flags & O_CLOEXEC) && io_fd_set_cloexec(result) == -1) {
		errsv = errno;
		goto error_set_cloexec;
	}
	if ((flags & O_NONBLOCK) && io_fd_set_nonblock(result) == -1) {
		errsv = errno;
		goto error_set_nonblock;
	}
#endif
	return result;

#if !LELY_HAVE_ACCEPT4
error_set_nonblock:
error_set_cloexec:
	close(result);
	errno = errsv;
	return -1;
#endif
}

int
io_fd_connect(int fd, const struct sockaddr *addr, socklen_t addrlen,
		int dontwait)
{
	int errsv = errno;
	// Try to establish a connection.
	int result = connect(fd, addr, addrlen);
	if (!result || (errno != EINPROGRESS && errno != EINTR) || dontwait)
		return result;
	// The connection is in progress; wait for it to be established.
	int events = POLLOUT;
	if (!io_fd_wait(fd, &events, -1)) {
		errno = errsv;
		// Obtain the result of the connection attempt.
		result = getsockopt(fd, SOL_SOCKET, SO_ERROR, &errsv,
				&(socklen_t){ sizeof(int) });
		if (!result && errsv) {
			result = -1;
			errno = errsv;
		}
	}
	return result;
}

ssize_t
io_fd_recvmsg(int fd, struct msghdr *msg, int flags, int timeout)
{
#ifdef MSG_DONTWAIT
	if (timeout >= 0)
		flags |= MSG_DONTWAIT;
#endif

	ssize_t result = 0;
	int errsv = errno;
	for (;;) {
		errno = errsv;
		// Try to receive a message.
		result = recvmsg(fd, msg, flags);
		if (result >= 0)
			break;
		if (errno == EINTR)
			continue;
		if (!timeout || (errno != EAGAIN && errno != EWOULDBLOCK))
			return -1;
		// Wait for a message to arrive.
		// clang-format off
		int events = (flags & MSG_OOB)
				? (POLLRDBAND | POLLPRI) : POLLRDNORM;
		// clang-format on
		if (io_fd_wait(fd, &events, timeout) == -1)
			return -1;
		// Since the timeout is relative, we can only use a positive
		// value once.
		if (timeout > 0)
			timeout = 0;
	}

	return result;
}

ssize_t
io_fd_sendmsg(int fd, const struct msghdr *msg, int flags, int timeout)
{
	flags |= MSG_NOSIGNAL;
#ifdef MSG_DONTWAIT
	if (timeout >= 0)
		flags |= MSG_DONTWAIT;
#endif

	ssize_t result = 0;
	int errsv = errno;
	for (;;) {
		errno = errsv;
		// Try to send a message.
		result = sendmsg(fd, msg, flags);
		if (result >= 0)
			break;
		if (errno == EINTR)
			continue;
		if (!timeout || (errno != EAGAIN && errno != EWOULDBLOCK))
			return -1;
		// Wait for the socket to become ready.
		int events = (flags & MSG_OOB) ? POLLWRBAND : POLLWRNORM;
		if (io_fd_wait(fd, &events, timeout) == -1)
			return -1;
		// Since the timeout is relative, we can only use a positive
		// value once.
		if (timeout > 0)
			timeout = 0;
	}
	return result;
}

#endif // _POSIX_C_SOURCE >= 200112L
