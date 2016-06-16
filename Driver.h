/*++

Module Name:

    driver.h

Abstract:

    This file contains the driver definitions.

Environment:

    Kernel-mode Driver Framework

--*/

#define INITGUID

#include <ntddk.h>
#include <wdf.h>

#include "Helper.h"
#include "device.h"
#include "queue.h"
#include "trace.h"

EXTERN_C_START

//
// WDFDRIVER Events
//

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD DriverTestEvtDeviceAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP DriverTestEvtDriverContextCleanup;

typedef struct _OBJECT_TYPE_INITIALIZER {
	USHORT Length;		// Uint2B
	USHORT type;
//		+ 0x002 ObjectTypeFlags : UChar
//		+ 0x002 CaseInsensitive : Pos 0, 1 Bit
//		+ 0x002 UnnamedObjectsOnly : Pos 1, 1 Bit
//		+ 0x002 UseDefaultObject : Pos 2, 1 Bit
//		+ 0x002 SecurityRequired : Pos 3, 1 Bit
//		+ 0x002 MaintainHandleCount : Pos 4, 1 Bit
//		+ 0x002 MaintainTypeList : Pos 5, 1 Bit
//		+ 0x002 SupportsObjectCallbacks : Pos 6, 1 Bit
//		+ 0x002 CacheAligned : Pos 7, 1 Bit
	UINT32 ObjectTypeCode;		// Uint4B
	UINT32 InvalidAttributes;	// Uint4B
	GENERIC_MAPPING GenericMapping;	//_GENERIC_MAPPING
	UINT32 ValidAccessMask;	// Uint4B
	UINT32 RetainAccess;	// Uint4B
	POOL_TYPE PoolType; // _POOL_TYPE
	UINT32 DefaultPagedPoolCharge;	// Uint4B
	UINT32 DefaultNonPagedPoolCharge;	// Uint4B
	PVOID DumpProcedure;	// Ptr64     void
	PVOID OpenProcedure;	// Ptr64     long
	PVOID CloseProcedure;	// Ptr64     void
	PVOID DeleteProcedure;	// Ptr64     void
	PVOID ParseProcedure;	// Ptr64     long
	PVOID SecurityProcedure;	// Ptr64     long
	PVOID QueryNameProcedure;	// Ptr64     long
	PVOID OkayToCloseProcedure;	// Ptr64     unsigned char
	UINT32 WaitObjectFlagMask;	// Uint4B
	UINT16 WaitObjectFlagOffset;	// Uint2B
	UINT16 WaitObjectPointerOffset;	// Uint2B
} OBJECT_TYPE_INITIALIZER_WIN10, *POBJECT_TYPE_INITIALIZER_WIN10;

typedef struct _OBJECT_TYPE_WIN10 {
	LIST_ENTRY TypeList;         //         : _LIST_ENTRY
	UNICODE_STRING Name;         //             : _UNICODE_STRING
	PVOID DefaultObject;         //    : Ptr32 Void
	ULONG Index;         //            : UChar
	ULONG TotalNumberOfObjects;         // : Uint4B
	ULONG TotalNumberOfHandles;         // : Uint4B
	ULONG HighWaterNumberOfObjects;         // : Uint4B
	ULONG HighWaterNumberOfHandles;         // : Uint4B
	OBJECT_TYPE_INITIALIZER_WIN10 TypeInfo;         //         : _OBJECT_TYPE_INITIALIZER
	PVOID TypeLock;         //         : _EX_PUSH_LOCK
	ULONG Key;         //              : Uint4B
	LIST_ENTRY CallbackList;         //     : _LIST_ENTRY
} OBJECT_TYPE_WIN10, *POBJECT_TYPE_WIN10;

EXTERN_C_END
