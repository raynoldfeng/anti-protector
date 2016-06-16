#include "driver.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, DriverTestCreateDevice)
#endif

ULONGLONG KeServiceDescriptortable;
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

PVOID GetSystemModuleBase(CHAR	* target_name) {
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
			return system_module_info->Module[i].Base;
		}
	}
	return NULL;

}