EXTERN_C_START
#define offset_drvobj_base 0x18

VOID GetKeServiceDescriptorTable();
PVOID GetSSDTFuncByIndex(INT32);
PVOID FindSignature(PVOID target, INT32 targetlen, PVOID sig, INT32 siglen);
PVOID GetKernelModuleInfo(CHAR	* target_name, PVOID* base, LONG* size);
VOID ResetValidAccess(PVOID dbgobjtype);
PLIST_ENTRY GetProcCallList();
//模块详细信息结构如下：
typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT PathLength;
	CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

//该结构如下：
typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG Count;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

//---------系统信息结构---------   
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemNotImplemented1,
	SystemProcessesAndThreadsInformation,
	SystemCallCounts,
	SystemConfigurationInformation,
	SystemProcessorTimes,
	SystemGlobalFlag,
	SystemNotImplemented2,
	SystemModuleInformation,
	SystemLockInformation,
	SystemNotImplemented3,
	SystemNotImplemented4,
	SystemNotImplemented5,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPagefileInformation,
	SystemInstructionEmulationCounts,
	SystemInvalidInfoClass1,
	SystemCacheInformation,
	SystemPoolTagInformation,
	SystemProcessorStatistics,
	SystemDpcInformation,
	SystemNotImplemented6,
	SystemLoadImage,
	SystemUnloadImage,
	SystemTimeAdjustment,
	SystemNotImplemented7,
	SystemNotImplemented8,
	SystemNotImplemented9,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemLoadAndCallImage,
	SystemPrioritySeparation,
	SystemNotImplemented10,
	SystemNotImplemented11,
	SystemInvalidInfoClass2,
	SystemInvalidInfoClass3,
	SystemTimeZoneInformation,
	SystemLookasideInformation,
	SystemSetTimeSlipEvent,
	SystemCreateSession,
	SystemDeleteSession,
	SystemInvalidInfoClass4,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemAddVerifier,
	SystemSessionProcessesInformation
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

NTSYSAPI
NTSTATUS
NTAPI
NtQuerySystemInformation(IN  SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN  ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL);


typedef struct _CALLBACK_BODY {
	LIST_ENTRY                  CallbackList;
	OB_OPERATION                Operations;
	ULONG                       Active;
	HANDLE						Handle;
	POBJECT_TYPE                ObjectType;
	POB_PRE_OPERATION_CALLBACK  PreOperation;
	POB_POST_OPERATION_CALLBACK PostOperation;
	EX_RUNDOWN_REF              RundownProtection;
} CALLBACK_BODY, *PCALLBACK_BODY;

typedef struct _CALLBACK_NODE {
	USHORT         Version;
	USHORT         OperationRegistrationCount;
	PVOID          RegistrationContext;
	UNICODE_STRING Altitude;
	CALLBACK_BODY  Entries[1];
} CALLBACK_NODE, *PCALLBACK_NODE;

OB_PREOP_CALLBACK_STATUS
PreCall(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation);
EXTERN_C_END