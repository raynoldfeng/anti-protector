#include "driver.h"

ULONGLONG KeServiceDescriptortable;
VOID 
ResetValidAccess(PVOID DbgkDebugObjectType)
{
	//_OBJECT_TYPE.TypeInfo
	UINT32* pTypeInfo = (PVOID)((ULONGLONG)DbgkDebugObjectType + 0x40);
	//_OBJECT_TYPE_INITIALIZER.ValidAccessMask
	UINT32* pValidAccessMask = (PVOID)((ULONGLONG)pTypeInfo + 0x1c);
	UINT32 AccessMask = *pValidAccessMask;
	*pValidAccessMask = 0x1f000f;
	DbgPrint("[ValidAccessMask] : %x -> %x \n", AccessMask, *pValidAccessMask);
}
VOID 
GetKeServiceDescriptorTable()
{
	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
	PUCHAR EndSearchAddress = StartSearchAddress + 0x500;
	PUCHAR i = NULL;
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	ULONG templong = 0;
	ULONGLONG addr = 0;

	for (i = StartSearchAddress; i<EndSearchAddress; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 1))
		{
			b1 = *i;
			b2 = *(i + 1);
			b3 = *(i + 2);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15) //4c8d15
			{
				memcpy(&templong, i + 3, 4);
				addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
				KeServiceDescriptortable = addr;
				return;
			}
		}
	}

	KeServiceDescriptortable = 0;
	return;
}

PVOID 
GetSSDTFuncByIndex(INT32 index) {
	ULONGLONG tablebase = *(ULONGLONG*)KeServiceDescriptortable;
	INT32 offset = (*(INT32*)(tablebase + index * 4)) >> 4;
	ULONGLONG func = offset + tablebase;
	return (PVOID)func;
}

PVOID
FindSignature(PVOID target, INT32 targetlen, PVOID sig, INT32 siglen) {
	int i, j;
	BOOLEAN flag;
	for (i = 0; i < targetlen; i++) {
		flag = TRUE;
		for (j = 0; j < siglen; j++) {
			int pos = i + j;
			if (*(char*)((ULONGLONG)target + pos) != *(char*)((ULONGLONG)sig + j)) {
				flag = FALSE;
				break;
			}
		}
		if (flag) {
			return (PVOID)((ULONGLONG)target + i);
		}
	}
	return NULL;
}

PVOID GetKernelModuleInfo(CHAR	* target_name, PVOID* base, LONG* size) {
	PVOID buffer = NULL;
	ULONG buf_size = 0x5000;
	NTSTATUS result;
	do {
		buffer = ExAllocatePool(PagedPool, buf_size);
		if (buffer == NULL) {
			return NULL;
		}
		ULONG need;
		result = NtQuerySystemInformation(SystemModuleInformation, buffer, buf_size, &need);
		if (result == STATUS_INFO_LENGTH_MISMATCH) {
			ExFreePool(buffer);
			buf_size *= 2;
		}
		else if (!NT_SUCCESS(result)) {
			ExFreePool(buffer);
			return NULL;
		}
	} while (result == STATUS_INFO_LENGTH_MISMATCH);

	PSYSTEM_MODULE_INFORMATION system_module_info = (PSYSTEM_MODULE_INFORMATION)buffer;
	int module_count = system_module_info->Count;
	for(int i=0; i<module_count; i++){
		CHAR* name = system_module_info->Module[i].ImageName + system_module_info->Module[i].PathLength;
		//DbgPrint("kernel module: %s,%p \n", name, system_module_info->Module[i].Base);
		if (_stricmp(name, target_name) == 0) {
			*base = system_module_info->Module[i].Base;
			*size = system_module_info->Module[i].Size;

		}
	}
	return NULL;

}

OB_PREOP_CALLBACK_STATUS
PreCall(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	PVOID unused1 = RegistrationContext;
	PVOID unused2 = pOperationInformation;
	ULONGLONG unused3 = 0;
	unused3 = (ULONGLONG)unused1 + (ULONGLONG)unused2;
	return OB_PREOP_SUCCESS;
}

PLIST_ENTRY 
GetProcCallList()
{
	NTSTATUS status;
	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;
	PCALLBACK_NODE obHandle;

	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obReg.Altitude, L"CallBack");
	memset(&opReg, 0, sizeof(opReg));//Init Struct
	opReg.ObjectType = PsProcessType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&PreCall;
	//opReg.PostOperation=(POB_POST_OPERATION_CALLBACK)&PostCall;
	obReg.OperationRegistration = &opReg;
	status = ObRegisterCallbacks(&obReg, &obHandle);
	if(NT_SUCCESS(status)){
		PLIST_ENTRY self = &(obHandle->Entries[0].CallbackList);
		ObUnRegisterCallbacks((PVOID)obHandle);
		return self->Blink;
	}
	else {
		DbgPrint("RegisterCallback failed! errcode:%x", status);
	}
	return NULL;
}

