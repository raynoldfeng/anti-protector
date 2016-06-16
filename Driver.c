/*++

Module Name:

    driver.c

Abstract:

    This file contains the driver entry points and callbacks.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "driver.tmh"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, DriverTestEvtDeviceAdd)
#pragma alloc_text (PAGE, DriverTestEvtDriverContextCleanup)
//#pragma alloc_text (PAGE, FindDebugObjectType)
#endif


NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:
    DriverEntry initializes the driver and is the first routine called by the
    system after the driver is loaded. DriverEntry specifies the other entry
    points in the function driver, such as EvtDevice and DriverUnload.

Parameters Description:

    DriverObject - represents the instance of the function driver that is loaded
    into memory. DriverEntry must initialize members of DriverObject before it
    returns to the caller. DriverObject is allocated by the system before the
    driver is loaded, and it is released by the system after the system unloads
    the function driver from memory.

    RegistryPath - represents the driver specific path in the Registry.
    The function driver can use the path to store driver related data between
    reboots. The path does not store hardware instance specific data.

Return Value:

    STATUS_SUCCESS if successful,
    STATUS_UNSUCCESSFUL otherwise.

--*/
{
    WDF_DRIVER_CONFIG config;
    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES attributes;

    //
    // Initialize WPP Tracing
    //
    WPP_INIT_TRACING( DriverObject, RegistryPath );

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    //
    // Register a cleanup callback so that we can call WPP_CLEANUP when
    // the framework driver object is deleted during driver unload.
    //
	GetKeServiceDescriptorTable();
	PVOID pNtCreateDebugObject = GetSSDTFuncByIndex(154);
	DbgPrint("[NtCreateDebugObject] address: %p\n", pNtCreateDebugObject);

	char DbgObjectTypeSig[] = {0x48, 0x83, 0x64, 0x24, 0x20, 0x00, 0x45, 0x8a, 0xca, 0x48, 0x8b, 0x15};
	PVOID addr = FindSignature(pNtCreateDebugObject, 0x100, DbgObjectTypeSig, sizeof(DbgObjectTypeSig));
	addr = (PVOID)((ULONGLONG)addr + sizeof(DbgObjectTypeSig));
	INT32 offset = *(INT32*)addr;
	PVOID DbgkDebugObjectType = *(PVOID*)(offset + (ULONGLONG)addr + 4);
	DbgPrint("[DbgkDebugObjectType] address: %p\n", DbgkDebugObjectType);
	//_OBJECT_TYPE.TypeInfo
	UINT32* pTypeInfo = (PVOID)((ULONGLONG)DbgkDebugObjectType + 0x40);
	//_OBJECT_TYPE_INITIALIZER.ValidAccessMask
	UINT32* pValidAccessMask = (PVOID)((ULONGLONG)pTypeInfo + 0x1c);
	UINT32 AccessMask = *pValidAccessMask;
	*pValidAccessMask = 0x1f000f;
	DbgPrint("[ValidAccessMask] : %x -> %x \n", AccessMask, *pValidAccessMask);
   
	PVOID tp_loader = GetSystemModuleBase("TesSafe.sys");
	DbgPrint("[Tessafe.sys] address: %p\n", tp_loader);

	WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = DriverTestEvtDriverContextCleanup;

    WDF_DRIVER_CONFIG_INIT(&config,
                           DriverTestEvtDeviceAdd
                           );

    status = WdfDriverCreate(DriverObject,
                             RegistryPath,
                             &attributes,
                             &config,
                             WDF_NO_HANDLE
                             );

    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "WdfDriverCreate failed %!STATUS!", status);
        WPP_CLEANUP(DriverObject);
        return status;
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit");

    return status;
}

NTSTATUS
DriverTestEvtDeviceAdd(
    _In_    WDFDRIVER       Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
    )
/*++
Routine Description:

    EvtDeviceAdd is called by the framework in response to AddDevice
    call from the PnP manager. We create and initialize a device object to
    represent a new instance of the device.

Arguments:

    Driver - Handle to a framework driver object created in DriverEntry

    DeviceInit - Pointer to a framework-allocated WDFDEVICE_INIT structure.

Return Value:

    NTSTATUS

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Driver);

    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    status = DriverTestCreateDevice(DeviceInit);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit");

    return status;
}

VOID
DriverTestEvtDriverContextCleanup(
    _In_ WDFOBJECT DriverObject
    )
/*++
Routine Description:

    Free all the resources allocated in DriverEntry.

Arguments:

    DriverObject - handle to a WDF Driver object.

Return Value:

    VOID.

--*/
{
    UNREFERENCED_PARAMETER(DriverObject);

    PAGED_CODE ();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    //
    // Stop WPP Tracing
    //
    WPP_CLEANUP( WdfDriverWdmGetDriverObject( (WDFDRIVER) DriverObject) );

}

