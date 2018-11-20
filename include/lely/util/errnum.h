/**@file
 * This header file is part of the utilities library; it contains the native and
 * platform-independent error number declarations.
 *
 * The C standard defines the (thread-local) `errno` variable plus a small
 * number of error numbers (which are guaranteed to be positive). POSIX
 * platforms extend the list of pre-defined error numbers to cover all
 * platform-specific errors. Windows defines a separate (thread-local) variable,
 * accessible by `GetLastError()`/`SetLastError()`, for all system errors. A
 * subset of these, accessible by `WSAGetLastError()`/`WSASetLastError()`, is
 * used for Windows Sockets errors. On top of this, both POSIX and Windows
 * maintain a list of error codes returned by the `getaddrinfo()` and
 * `getnameinfo()` functions. On Windows these error codes have the same values
 * as their corresponding system errors, while on Linux they all have negative
 * values, allowing them to be distinguished from valid `errno` values.
 * Unfortunately on Cygwin their values are positive and overlap with `errno`
 * error numbers.
 *
 * In order to minimize information loss, we would like to keep track of
 * platform-dependent error numbers when storing or propagating errors, but do
 * so in a platform-independent way. The #errc_t data type can be used to store
 * native error codes, while get_errc() and set_errc() provide access to the
 * current (thread-local) error code. These functions are equivalent to
 * `GetLastError()` and `SetLastError()` on Windows and map to `errno` on other
 * platforms. Negative `errno` values are used to store the error codes returned
 * by `getaddrinfo()` and `getnameinfo()`, even if the original error codes are
 * positive (e.g., on Cygwin). Since Windows also uses `errno` (for standard C
 * functions), `set_errno(errno)` can be used to portably translate `errno` to a
 * native error code(this is a no-op on POSIX platforms).
 *
 * When responding to errors it is desirable to have a list of
 * platform-independent error numbers. The #errnum_t data type provides the
 * `ERRNUM_*` error values. These values are guaranteed to be positive, unique
 * and to have the same value across all platforms. There is an `ERRNUM_*` value
 * for each of the (non-reserved) POSIX error numbers as well as the error codes
 * returned by `getaddrinfo()` and `getnameinfo()`. Translating between native
 * and platform-independent error numbers can be  done with errc2num() and
 * errnum2c().
 *
 * @copyright 2016-2018 Lely Industries N.V.
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

#ifndef LELY_UTIL_ERRNUM_H_
#define LELY_UTIL_ERRNUM_H_

#include <lely/util/util.h>

#include <errno.h>

#ifdef _WIN32
#include <winerror.h>
#elif _POSIX_C_SOURCE >= 200112L
#include <netdb.h>
#endif

#ifndef LELY_UTIL_ERRNUM_INLINE
#define LELY_UTIL_ERRNUM_INLINE inline
#endif

/// The native error code type.
#ifdef _WIN32
typedef DWORD errc_t;
#else
typedef int errc_t;
#endif

/// The platform-independent error numbers.
enum errnum {
	__ERRNUM_MIN,
	/// Argument list too long.
	ERRNUM_2BIG,
	/// Permission denied.
	ERRNUM_ACCES,
	/// Address in use.
	ERRNUM_ADDRINUSE,
	/// Address not available.
	ERRNUM_ADDRNOTAVAIL,
	/// Address family not supported.
	ERRNUM_AFNOSUPPORT,
	/// Resource unavailable, try again.
	ERRNUM_AGAIN,
	/// Connection already in progress.
	ERRNUM_ALREADY,
	/// Bad file descriptor.
	ERRNUM_BADF,
	/// Bad message.
	ERRNUM_BADMSG,
	/// Device or resource busy.
	ERRNUM_BUSY,
	/// Operation canceled.
	ERRNUM_CANCELED,
	/// No child process.
	ERRNUM_CHILD,
	/// Connection aborted.
	ERRNUM_CONNABORTED,
	/// Connection refused.
	ERRNUM_CONNREFUSED,
	/// Connection reset.
	ERRNUM_CONNRESET,
	/// Resource deadlock would occur.
	ERRNUM_DEADLK,
	/// Destination address required.
	ERRNUM_DESTADDRREQ,
	/// Mathematics argument out of domain of function.
	ERRNUM_DOM,
	// ERRNUM_DQUOT,
	/// File exists.
	ERRNUM_EXIST,
	/// Bad address.
	ERRNUM_FAULT,
	/// File too large.
	ERRNUM_FBIG,
	/// Host is unreachable.
	ERRNUM_HOSTUNREACH,
	/// Identifier removed.
	ERRNUM_IDRM,
	/// Illegal byte sequence.
	ERRNUM_ILSEQ,
	/// Operation in progress.
	ERRNUM_INPROGRESS,
	/// Interrupted function.
	ERRNUM_INTR,
	/// Invalid argument.
	ERRNUM_INVAL,
	/// I/O error.
	ERRNUM_IO,
	/// Socket is connected.
	ERRNUM_ISCONN,
	/// Is a directory.
	ERRNUM_ISDIR,
	/// Too many levels of symbolic links.
	ERRNUM_LOOP,
	/// File descriptor value too large.
	ERRNUM_MFILE,
	/// Too many links.
	ERRNUM_MLINK,
	/// Message too large.
	ERRNUM_MSGSIZE,
	// ERRNUM_MULTIHOP,
	/// Filename too long.
	ERRNUM_NAMETOOLONG,
	/// Network is down.
	ERRNUM_NETDOWN,
	/// Connection aborted by network.
	ERRNUM_NETRESET,
	/// Network unreachable.
	ERRNUM_NETUNREACH,
	/// Too many files open in system.
	ERRNUM_NFILE,
	/// No buffer space available.
	ERRNUM_NOBUFS,
	/// No message is available on the STREAM head read queue.
	ERRNUM_NODATA,
	/// No such device.
	ERRNUM_NODEV,
	/// No such file or directory.
	ERRNUM_NOENT,
	/// Executable file format error.
	ERRNUM_NOEXEC,
	/// No locks available.
	ERRNUM_NOLCK,
	// ERRNUM_NOLINK,
	/// Not enough space.
	ERRNUM_NOMEM,
	/// No message of the desired type.
	ERRNUM_NOMSG,
	/// Protocol not available.
	ERRNUM_NOPROTOOPT,
	/// No space left on device.
	ERRNUM_NOSPC,
	/// No STREAM resources.
	ERRNUM_NOSR,
	/// Not a STREAM.
	ERRNUM_NOSTR,
	/// Function not supported.
	ERRNUM_NOSYS,
	/// The socket is not connected.
	ERRNUM_NOTCONN,
	/// Not a directory or a symbolic link to a directory.
	ERRNUM_NOTDIR,
	/// Directory not empty.
	ERRNUM_NOTEMPTY,
	/// State not recoverable.
	ERRNUM_NOTRECOVERABLE,
	/// Not a socket.
	ERRNUM_NOTSOCK,
	/// Not supported.
	ERRNUM_NOTSUP,
	/// Inappropriate I/O control operation.
	ERRNUM_NOTTY,
	/// No such device or address.
	ERRNUM_NXIO,
	/// Operation not supported on socket.
	ERRNUM_OPNOTSUPP,
	/// Value too large to be stored in data type.
	ERRNUM_OVERFLOW,
	/// Previous owner died.
	ERRNUM_OWNERDEAD,
	/// Operation not permitted.
	ERRNUM_PERM,
	/// Broken pipe.
	ERRNUM_PIPE,
	/// Protocol error.
	ERRNUM_PROTO,
	/// Protocol not supported.
	ERRNUM_PROTONOSUPPORT,
	/// Protocol wrong type for socket.
	ERRNUM_PROTOTYPE,
	/// Result too large.
	ERRNUM_RANGE,
	/// Read-only file system.
	ERRNUM_ROFS,
	/// Invalid seek.
	ERRNUM_SPIPE,
	/// No such process.
	ERRNUM_SRCH,
	// ERRNUM_STALE,
	/// Stream ioctl() timeout.
	ERRNUM_TIME,
	/// Connection timed out.
	ERRNUM_TIMEDOUT,
	/// Text file busy.
	ERRNUM_TXTBSY,
	/// Operation would block.
	ERRNUM_WOULDBLOCK,
	/// Cross-device link.
	ERRNUM_XDEV,
	/**
	 * The name could not be resolved at this time. Future attempts may
	 * succeed.
	 */
	ERRNUM_AI_AGAIN,
	/// The flags had an invalid value.
	ERRNUM_AI_BADFLAGS,
	/// A non-recoverable error occurred.
	ERRNUM_AI_FAIL,
	/**
	 * The address family was not recognized or the address length was
	 * invalid for the specified family.
	 */
	ERRNUM_AI_FAMILY,
	/// There was a memory allocation failure.
	ERRNUM_AI_MEMORY,
	/// The name does not resolve for the supplied parameters.
	ERRNUM_AI_NONAME,
	/// An argument buffer overflowed.
	ERRNUM_AI_OVERFLOW,
	/// The service passed was not recognized for the specified socket type.
	ERRNUM_AI_SERVICE,
	/// The intended socket type was not recognized.
	ERRNUM_AI_SOCKTYPE,
	__ERRNUM_MAX
};

/// The platform-independent error number type.
#ifdef __cplusplus
typedef int errnum_t;
#else
typedef enum errnum errnum_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Transforms a standard C error number to a native error code. This is
 * equivalent to `errnum2c(errno2num(errnum))` on Windows, or `errnum` on other
 * platforms.
 *
 * @see errc2no()
 */
LELY_UTIL_EXTERN errc_t errno2c(int errnum);

/**
 * Transforms a standard C error number to a platform-independent error number.
 *
 * @see errnum2no()
 */
LELY_UTIL_EXTERN errnum_t errno2num(int errnum);

/**
 * Transforms a native error code to a standard C error number. This is
 * equivalent to `errnum2no(errc2num(errc))` on Windows, or `errc` on other
 * platforms (provided `errc` is positive).
 *
 * @see errc2no()
 */
LELY_UTIL_EXTERN int errc2no(errc_t errc);

/**
 * Transforms a native error code to a platform-independent error number.
 *
 * @see errnum2c()
 */
LELY_UTIL_EXTERN errnum_t errc2num(errc_t errc);

/**
 * Transforms a platform-independent error number to a standard C error number.
 *
 * @see errno2num()
 */
LELY_UTIL_EXTERN int errnum2no(errnum_t errnum);

/**
 * Transforms a platform-independent error number to a native error code.
 *
 * @see err2num()
 */
LELY_UTIL_EXTERN errc_t errnum2c(errnum_t errnum);

/**
 * Returns the last (thread-specific) standard C error number set by a system
 * call or library function. This is equivalent to `errc2no(get_errc())`.
 *
 * @see set_errno()
 */
LELY_UTIL_ERRNUM_INLINE int get_errno(void);

/**
 * Sets the current (thread-specific) standard C error number to <b>errnum</b>.
 * This is equivalent to `set_errc(errno2c(errnum))`.
 *
 * @see get_errno()
 */
LELY_UTIL_ERRNUM_INLINE void set_errno(int errnum);

/**
 * Returns the last (thread-specific) native error code set by a system call or
 * library function. This is equivalent to `GetLastError()`/`WSAGetLastError()`
 * on Windows, or `errno` on other platforms.
 *
 * This function returns the thread-specific error number.
 *
 * @see set_errc()
 */
LELY_UTIL_EXTERN errc_t get_errc(void);

/**
 * Sets the current (thread-specific) native error code to <b>errc</b>. This is
 * equivalent to `SetLastError(errc)`/`WSASetLastError(errc)` on Windows, or
 * `errno = errc` on other platforms.
 *
 * @see get_errc()
 */
LELY_UTIL_EXTERN void set_errc(errc_t errc);

/**
 * Returns the last (thread-specific) platform-independent error number set by a
 * system call or library function. This is equivalent to
 * `errc2num(get_errc())`.
 *
 * @see set_errnum()
 */
LELY_UTIL_ERRNUM_INLINE errnum_t get_errnum(void);

/**
 * Sets the current (thread-specific) platform-independent error number to
 * <b>errnum</b>. This is equivalent to `set_errc(errnum2c(errnum))`.
 *
 * @see get_errnum()
 */
LELY_UTIL_ERRNUM_INLINE void set_errnum(errnum_t errnum);

/**
 * Returns a string describing a standard C error number. This is equivalent to
 * `strerror(errnum)`.
 */
LELY_UTIL_EXTERN const char *errno2str(int errnum);

/// Returns a string describing a native error code.
LELY_UTIL_EXTERN const char *errc2str(errc_t errc);

/**
 * Returns a string describing a platform-independent error number. This is
 * equivalent to `errc2str(errnum2c(errnum))`.
 */
LELY_UTIL_ERRNUM_INLINE const char *errnum2str(errnum_t errnum);

LELY_UTIL_ERRNUM_INLINE int
get_errno(void)
{
	return errc2no(get_errc());
}

LELY_UTIL_ERRNUM_INLINE void
set_errno(int errnum)
{
	set_errc(errno2c(errnum));
}

LELY_UTIL_ERRNUM_INLINE errnum_t
get_errnum(void)
{
	return errc2num(get_errc());
}

LELY_UTIL_ERRNUM_INLINE void
set_errnum(errnum_t errnum)
{
	set_errc(errnum2c(errnum));
}

LELY_UTIL_ERRNUM_INLINE const char *
errnum2str(errnum_t errnum)
{
	return errc2str(errnum2c(errnum));
}

#ifdef __cplusplus
}
#endif

#endif // !LELY_UTIL_ERRNUM_H_
