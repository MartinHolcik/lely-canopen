/**@file
 * This is the internal header file of the Windows-specific I/O declarations.
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

#ifndef LELY_IO2_INTERN_WIN32_IO_H_
#define LELY_IO2_INTERN_WIN32_IO_H_

#include "../io2.h"

#if _WIN32

#ifndef _NTDEF_
typedef LONG NTSTATUS;
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#if defined(__MINGW32__) && !defined(__UNICODE_STRING_DEFINED)
#define __UNICODE_STRING_DEFINED
#endif
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

#if defined(__MINGW32__) && !defined(__OBJECT_ATTRIBUTES_DEFINED)
#define __OBJECT_ATTRIBUTES_DEFINED
#endif
typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p, n, a, r, s) \
	{ \
		(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
		(p)->RootDirectory = (r); \
		(p)->Attributes = (a); \
		(p)->ObjectName = (n); \
		(p)->SecurityDescriptor = (s); \
		(p)->SecurityQualityOfService = NULL; \
	}
#endif

typedef struct _IO_STATUS_BLOCK {
#ifdef __MINGW32__
	__extension__ union {
#else
	union {
#endif
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

#ifdef __cplusplus
extern "C" {
#endif

typedef NTSTATUS(NTAPI *LPFN_NTCREATEFILE)(PHANDLE FileHandle,
		ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
		PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize,
		ULONG FileAttributes, ULONG ShareAccess,
		ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer,
		ULONG EaLength);
extern LPFN_NTCREATEFILE lpfnNtCreateFile;

typedef void(NTAPI *LPFN_RTLINITUNICODESTRING)(
		PUNICODE_STRING DestinationString, PCWSTR SourceString);
extern LPFN_RTLINITUNICODESTRING lpfnRtlInitUnicodeString;

typedef ULONG(NTAPI *LPFN_RTLNTSTATUSTODOSERROR)(NTSTATUS Status);
extern LPFN_RTLNTSTATUSTODOSERROR lpfnRtlNtStatusToDosError;

int io_win32_ntdll_init(void);
void io_win32_ntdll_fini(void);

int io_win32_sigset_init(void);
void io_win32_sigset_fini(void);

int io_win32_wsa_init(void);
void io_win32_wsa_fini(void);

HANDLE io_win32_tls_get_event(void);

#ifdef __cplusplus
}
#endif

#endif // _WIN32

#endif // LELY_IO2_INTERN_WIN32_IO_H_
