#pragma once
#pragma warning( disable: 4100 4101 4103 4189 4996 6271 6066 6273 6328)
#pragma runtime_checks("", off)
#pragma optimize("", off)
#pragma strict_gs_check(off)

// headers

#include <ntifs.h>
#include <minwindef.h>
#include <wdm.h>

// driver name defines

#define RL_DEVICE_NAME L"\\Device\\KernelPISCreator"
#define RL_SYM_NAME L"\\??\\KernelPISCreator"
#define RL_USER_SYM_NAME L"\\\\.\\KernelPISCreator"

// driver ioctl code defines

#define IOCTL_UNKNOWN_BASE					FILE_DEVICE_UNKNOWN
#define IOCTL_ALLOCATEMEM_NONPAGED    CTL_CODE(IOCTL_UNKNOWN_BASE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MAP_MEMORY						CTL_CODE(IOCTL_UNKNOWN_BASE, 0x084d, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_GETPROCADDRESS		CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0802, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_CREATE_DRIVER		CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0806, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_UNMAP_MEMORY					CTL_CODE(IOCTL_UNKNOWN_BASE, 0x084e, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

// function prototypes

extern "C"
NTSTATUS
__declspec(safebuffers)
__declspec(noinline) PicStart(UINT64 StartContext);
#pragma alloc_text(".PIS", "PicStart")


extern "C"
NTSTATUS
__declspec(safebuffers)
__declspec(noinline)
__stdcall  HookedDispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
#pragma alloc_text(".PIS2", "HookedDispatchIoctl")


typedef PVOID(__stdcall* pMmGetSystemRoutineAddress)(_In_ PUNICODE_STRING  SystemRoutineName);
typedef NTSTATUS(__stdcall* pRtlCopyMemory)(_In_  PVOID Destination, _In_  const PVOID Source, _In_ SIZE_T Length);
typedef PEPROCESS(__stdcall* pIoGetCurrentProcess)();
typedef HANDLE(__stdcall* pPsGetProcessId)(_In_ PEPROCESS Process);
typedef ULONG(__stdcall* pDbgPrint)(_In_ PCSTR Format, ...);
typedef NTSTATUS(__stdcall* pObReferenceObjectByName)(
	__in PUNICODE_STRING ObjectName,
	__in ULONG Attributes,
	__in_opt PACCESS_STATE AccessState,
	__in_opt ACCESS_MASK DesiredAccess,
	__in POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__inout_opt PVOID ParseContext,
	__out PVOID* Object);
typedef LONG_PTR(__stdcall* pObfDereferenceObject)(_In_  PVOID Object);
typedef LONG_PTR(__stdcall* pRtlInitUnicodeString)(PUNICODE_STRING  DestinationString, PCWSTR SourceString);
typedef PVOID(__stdcall* p_InterlockedExchangePointerString)(PVOID* Target, _In_ PVOID Value);
typedef NTSTATUS(__stdcall* pIoCreateDriver)(_In_  PUNICODE_STRING DriverName, _In_  PDRIVER_INITIALIZE InitializationFunction);
typedef PVOID(__stdcall* pExAllocatePool)(__drv_strictTypeMatch(__drv_typeExpr) _In_ POOL_TYPE PoolType, _In_ SIZE_T NumberOfBytes);
typedef VOID(__stdcall* pMmUnmapLockedPages)(_In_ PVOID BaseAddress, _Inout_ PMDL MemoryDescriptorList);
typedef VOID(__stdcall* pMmUnlockPages)(_Inout_ PMDL MemoryDescriptorList);
typedef VOID(__stdcall* pIoFreeMdl)(PMDL Mdl);
typedef NTSTATUS(__stdcall* pPsLookupProcessByProcessId)(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);
typedef VOID(__stdcall* pKeStackAttachProcess)(_Inout_ PRKPROCESS PROCESS, _Out_ PRKAPC_STATE ApcState);
typedef PMDL(__stdcall* pIoAllocateMdl)(_In_opt_ __drv_aliasesMem PVOID VirtualAddress,
	_In_ ULONG Length,
	_In_ BOOLEAN SecondaryBuffer,
	_In_ BOOLEAN ChargeQuota,
	_Inout_opt_ PIRP Irp);
typedef VOID(__stdcall* pMmProbeAndLockPages)(_Inout_ PMDL MemoryDescriptorList, _In_ KPROCESSOR_MODE AccessMode, _In_ LOCK_OPERATION Operation);
typedef VOID(__stdcall* pKeUnstackDetachProcess)(_In_ PRKAPC_STATE ApcState);
typedef PVOID(__stdcall* pMmMapLockedPagesSpecifyCache)(_Inout_ PMDL MemoryDescriptorList,
	_In_ __drv_strictType(KPROCESSOR_MODE / enum _MODE, __drv_typeConst)
	KPROCESSOR_MODE AccessMode,
	_In_ __drv_strictTypeMatch(__drv_typeCond) MEMORY_CACHING_TYPE CacheType,
	_In_opt_ PVOID RequestedAddress,
	_In_     ULONG BugCheckOnFailure,
	_In_     ULONG Priority  // MM_PAGE_PRIORITY logically OR'd with MdlMapping*
	);
typedef VOID(__stdcall* pIofCompleteRequest)(_In_ PIRP Irp, _In_ CCHAR PriorityBoost);

// pic parameter structure 

struct KernelPisParameters
{
	LPVOID MmGetSystemRoutineAddress;
	LPVOID HookFunctionAddress;
	WCHAR DriverObjectName[100];
	USHORT dummy2;
};

NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

void Unload(_In_ PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(RL_SYM_NAME);
	// delete symbolic link
	IoDeleteSymbolicLink(&symLink);

	// delete device object
	IoDeleteDevice(DriverObject->DeviceObject);

	DbgPrint("PISCreator unloaded\n");
}

NTSTATUS OriginalDispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	DbgPrint("Hello From OriginalDispatchIoctl!");
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
