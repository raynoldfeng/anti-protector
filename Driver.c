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
#pragma alloc_text (PAGE, DriverTestEvtDriverUnload)
//#pragma alloc_text (PAGE, FindDebugObjectType)
#endif


VOID DriverTestEvtDriverUnload(
	_In_
	WDFDRIVER Driver
	)
{
	DbgPrint("DriverTestEvtDriverUnload \n", Driver);
	/*该方法会导致驱动卸载时崩溃，改为修改保护列表
	if (tp_psproctype) {
		*tp_psproctype = PsProcessType;
	}*/
}

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

	DbgPrint("DriverEntry\n");
    WDF_DRIVER_CONFIG config;
    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES attributes;

	// 绕过MmVerifyCallbackFunction，否则无法挂钩回掉
	PCHAR pflag = (PVOID)((ULONGLONG)DriverObject->DriverSection + 0x68);
	*pflag = *pflag | 0x20;
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
	PVOID DbgObjAdr = FindSignature(pNtCreateDebugObject, 0x100, DbgObjectTypeSig, sizeof(DbgObjectTypeSig));
	DbgObjAdr = (PVOID)((ULONGLONG)DbgObjAdr + sizeof(DbgObjectTypeSig));
	INT32 offset = *(INT32*)DbgObjAdr;
	PVOID DbgkDebugObjectType = *(PVOID*)(offset + (ULONGLONG)DbgObjAdr + 4);
	DbgPrint("[DbgkDebugObjectType] address: %p\n", DbgkDebugObjectType);
   
	PVOID tp_loader_base = NULL;
	LONG tp_loader_size = 0;
	GetKernelModuleInfo("TesSafe.sys", &tp_loader_base, &tp_loader_size);
	if (tp_loader_base != NULL) {
		DbgPrint("[Tessafe.sys] address: %p\n", tp_loader_base);

		PVOID* global_drvobjlist = (PVOID*)((ULONGLONG)tp_loader_base + offset_drvobjlist);
		PVOID* pmodule_list = *global_drvobjlist;
		LONGLONG module_count = *(LONGLONG*)((ULONGLONG)pmodule_list + 0x10);
		DbgPrint("kernal moudule list: %p, count:%x \n", pmodule_list, module_count);

		PVOID modulebase;
		PVOID* pmodule = *pmodule_list;
		PVOID tessafe = NULL;
		while (module_count) {
			modulebase = *(PVOID*)((ULONGLONG)*pmodule + offset_drvobj_base);
			//一串TEXT段开头的特征码
			char tpsig[] = {0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x30};
			PVOID tpsig_adr = FindSignature(modulebase, 0x2000, tpsig, sizeof(tpsig));
			if (tpsig_adr) {
				tessafe = modulebase;
				DbgPrint("Tessafe module address: %p\n", modulebase);
				//找TP里保存的DebugObjectType
				PVOID* tp_dbgtype = FindSignature(modulebase, 0x20000, DbgkDebugObjectType, sizeof(PVOID));
				if (tp_dbgtype) {
					DbgPrint("Tessafe gDebugObjectType address: %p\n", tp_dbgtype);
					*tp_dbgtype = 0;
					ResetValidAccess(DbgkDebugObjectType);
				}
				//找TP里的PsProcType
				//该方法会导致TP卸载崩溃
				/*tp_psproctype = FindSignature(modulebase, 0x20000, &PsProcessType, sizeof(PVOID));
				if (tp_psproctype) {
					DbgPrint("Tessafe extended PsProcessType address: %p\n", tp_psproctype);
					*tp_psproctype = IoFileObjectType;
					
				}*/
				char sigDbgPrintDump[] = {0x4c, 0x8b, 0xdc, 0x49, 0x89, 0x4b, 0x08 };
				PVOID DbgPrintDump = FindSignature(tp_loader_base, 0x10000, sigDbgPrintDump, sizeof(sigDbgPrintDump));
				DbgPrint("loader's DbgPrintDump address: %p\n", DbgPrintDump);
				//被保护进程列表在gLPDbgPrintDump前一个
				PVOID gLPDbgPrintDump = FindSignature(modulebase, 0x20000, &DbgPrintDump, sizeof(PVOID));
				PVOID* protect_list = (PVOID*)((ULONGLONG)gLPDbgPrintDump - sizeof(PVOID));
				DbgPrint("proctect list: %p\n", protect_list);
				*protect_list = NULL;
			}
			else {
				DbgPrint("kernal moudule address: %p\n", modulebase);
			}
			pmodule++;
			module_count--;
		}		
	}

	UNICODE_STRING disabledbg;
	RtlInitUnicodeString(&disabledbg, L"KdDisableDebugger");
	PVOID disabledbg_adr = MmGetSystemRoutineAddress(&disabledbg);
	DbgPrint("KdDisableDebugger address: %p\n", disabledbg_adr);
	
	PLIST_ENTRY entry = GetProcCallList();
	if (entry) {
		PLIST_ENTRY back = entry->Blink;
		while (back != entry) {
			PCALLBACK_BODY pnode = (PCALLBACK_BODY)back;
			ULONGLONG pre_func = (ULONGLONG)pnode->PreOperation;
			ULONGLONG post_func = (ULONGLONG)pnode->PostOperation;

			if (((pre_func > (ULONGLONG)tp_loader_base) && (pre_func < (ULONGLONG)tp_loader_base + tp_loader_size)) ||
				(post_func > (ULONGLONG)tp_loader_base) && (post_func < (ULONGLONG)tp_loader_base + tp_loader_size)) {
	//			ObUnRegisterCallbacks(pnode->Handle);
				DbgPrint("Tessafe registered Callback function pre:%p post:%p\n", pre_func, post_func);
			}
			back = back->Blink;
		}
	}


	WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
	attributes.EvtCleanupCallback = DriverTestEvtDriverContextCleanup;

    WDF_DRIVER_CONFIG_INIT(&config,
                           NULL
                           );

	config.DriverInitFlags = WdfDriverInitNonPnpDriver;  //非pnp
	config.EvtDriverUnload = DriverTestEvtDriverUnload;  //卸载函

    status = WdfDriverCreate(DriverObject,
                             RegistryPath,
                             &attributes,
                             &config,
                             WDF_NO_HANDLE
                             );

    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "WdfDriverCreate failed %!STATUS!", status);
		DbgPrint("Entry failed exit :%x\n", status);
        WPP_CLEANUP(DriverObject);
        return status;
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit");
	DbgPrint("Entry successed exit :%x\n", status);
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
	DbgPrint("DriverTestEvtDeviceAdd \n");

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
	DbgPrint("DriverTestEvtDriverContextCleanup \n");
    UNREFERENCED_PARAMETER(DriverObject);

    PAGED_CODE ();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    //
    // Stop WPP Tracing
    //
    WPP_CLEANUP( WdfDriverWdmGetDriverObject( (WDFDRIVER) DriverObject) );

}

