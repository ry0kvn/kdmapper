#include <ntifs.h>
#include <minwindef.h>
#include <wdm.h>

#define DRIVER_PREFIX "KernelPISCreator"
#define DRIVER_TAG 'kpic'

struct KernelPisParameters
{
	LPVOID MmGetSystemRoutineAddress;
	LPVOID ReturnedDataAddress;
	USHORT ReturnedDataMaxSize;
};

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

#pragma runtime_checks("", off)
#pragma optimize("", off)
#pragma strict_gs_check(off)

extern "C" void
__declspec(safebuffers)
__declspec(noinline) PicStart(PVOID StartContext);

#pragma alloc_text(".PIS", "PicStart")

void
__declspec(safebuffers)
__declspec(noinline)
__stdcall PicStart(PVOID StartContext)
{
	// __debugbreak(); // INT 3 for debugging

	if (NULL == StartContext)
		return;

	KernelPisParameters* pisParameters = (KernelPisParameters*)StartContext;

	// Get MmGetSystemRoutineAddress
	pMmGetSystemRoutineAddress mmGetSystemRoutineAddress = (pMmGetSystemRoutineAddress)pisParameters->MmGetSystemRoutineAddress;
	if (NULL == mmGetSystemRoutineAddress)
		return;
	
	// Function names		
	WCHAR ioGetCurrentProcessName[] = { 'P','s','G','e','t','C','u','r','r','e','n','t','P','r','o','c','e','s','s','\0' };
	WCHAR psGetProcessIdName[] = { 'P','s','G','e','t','P','r','o','c','e','s','s','I','d','\0' };
	WCHAR rtlCopyMemoryName[] = { 'R','t','l','C','o','p','y','M','e','m','o','r','y','\0' };
	WCHAR DbgPrintName[] = { 'D', 'b', 'g', 'P', 'r', 'i', 'n', 't', '\0' };
	WCHAR  greeting[] = { 'H', 'e', 'l', 'l', 'o', ' ', 'f', 'r', 'o', 'm', ' ', 'K', 'e', 'r', 'n', 'e', 'l', ' ', 'm', 'o', 'd', 'e', ' ', 's', 'h', 'e', 'l', 'l', 'c', 'o', 'd', 'e', '!', '\0' };
	WCHAR end[] = { 'S', 'h', 'e', 'l', 'l', 'c', 'o', 'd', 'e', ' ', 's', 'u', 'c', 'c', 'e', 's', 's', 'f', 'u', 'l', 'l', 'y', ' ', 'e', 'x', 'e', 'c', 'u', 't', 'e', 'd', '!', '\0' };

	// Create UNICODE_STRING structures
	UNICODE_STRING ioGetCurrentProcessString = RTL_CONSTANT_STRING(ioGetCurrentProcessName);
	UNICODE_STRING psGetProcessIdString = RTL_CONSTANT_STRING(psGetProcessIdName);
	UNICODE_STRING rtlCopyMemoryString = RTL_CONSTANT_STRING(rtlCopyMemoryName);
	UNICODE_STRING dbgPrint = RTL_CONSTANT_STRING(DbgPrintName);

	// Get function addresses
	pIoGetCurrentProcess ioGetCurrentProcess = (pIoGetCurrentProcess)mmGetSystemRoutineAddress(&ioGetCurrentProcessString);
	pPsGetProcessId psGetProcessId = (pPsGetProcessId)mmGetSystemRoutineAddress(&psGetProcessIdString);
	pRtlCopyMemory rtlCopyMemory = (pRtlCopyMemory)mmGetSystemRoutineAddress(&rtlCopyMemoryString);
	pDbgPrint myDbgPrint = (pDbgPrint)mmGetSystemRoutineAddress(&dbgPrint);

	myDbgPrint("%ls", greeting);

	// Check addresses validity
	if (NULL == ioGetCurrentProcess || NULL == psGetProcessId || NULL == rtlCopyMemory)
		return;

	// Get current process object	
	PEPROCESS process = ioGetCurrentProcess();
	if (NULL == process)
		return;

	// Convert to ULONG and copy to returned data address
	ULONG pid = ::HandleToULong(psGetProcessId(process));
	rtlCopyMemory(pisParameters->ReturnedDataAddress, &pid, sizeof(pid));

	//////////////////////////////
	// my code start
	
	// \\driver\\EvilCEDRIVER73
	//WCHAR driverNameString[] = { '\\', '\\', 'd', 'r', 'i', 'v', 'e', 'r', '\\', '\\', 'E', 'v', 'i', 'l', 'C', 'E', 'D', 'R', 'I', 'V', 'E', 'R', '7', '3', 0};
	WCHAR driverObjectNameString[] = { '\\', 'D', 'r', 'i', 'v', 'e', 'r', '\\', 'K', 'e', 'r', 'n', 'e', 'l', 'P', 'I', 'S', 'C', 'r', 'e', 'a', 't', 'o', 'r', 0};
	WCHAR ObReferenceObjectByNameString[] = { 'O', 'b', 'R', 'e', 'f', 'e', 'r', 'e', 'n', 'c', 'e', 'O', 'b', 'j', 'e', 'c', 't', 'B', 'y', 'N', 'a', 'm', 'e', 0 };
	WCHAR ObfDereferenceObjectString[] = { 'O', 'b', 'f', 'D', 'e', 'r', 'e', 'f', 'e', 'r', 'e', 'n', 'c', 'e', 'O', 'b', 'j', 'e', 'c', 't', 0 };
	WCHAR IoDriverObjectTypeString[] = { 'I', 'o', 'D', 'r', 'i', 'v', 'e', 'r', 'O', 'b', 'j', 'e', 'c', 't', 'T', 'y', 'p', 'e', 0 };

	// Create UNICODE_STRING structures
	UNICODE_STRING driverObjectName = RTL_CONSTANT_STRING(driverObjectNameString);
	UNICODE_STRING obReferenceObjectByNameString = RTL_CONSTANT_STRING(ObReferenceObjectByNameString);
	UNICODE_STRING obfDereferenceObjectString = RTL_CONSTANT_STRING(ObfDereferenceObjectString);
	UNICODE_STRING ioDriverObjectTypeString = RTL_CONSTANT_STRING(IoDriverObjectTypeString);

	// Get function addresses
	pObReferenceObjectByName obReferenceObjectByName = (pObReferenceObjectByName)mmGetSystemRoutineAddress(&obReferenceObjectByNameString);
	pObfDereferenceObject obfDereferenceObject = (pObfDereferenceObject)mmGetSystemRoutineAddress(&obfDereferenceObjectString);
	POBJECT_TYPE* ioDriverObjectType = (POBJECT_TYPE*)mmGetSystemRoutineAddress(&ioDriverObjectTypeString);

	myDbgPrint("obReferenceObjectByName %p", obReferenceObjectByName);
	myDbgPrint("obfDereferenceObject %p", obfDereferenceObject);

	// Local variables
	PDRIVER_OBJECT DriverObject;

	auto status = obReferenceObjectByName(&driverObjectName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		0,
		*ioDriverObjectType,
		KernelMode,
		NULL,
		(PVOID*)&DriverObject);

	if (NT_SUCCESS(status)) {
		myDbgPrint("Target driver object: 0x%p", DriverObject);
	}

	// Hook IRP_MJ_DEVICE_CONTROL
	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
		auto  MjFunc = (PVOID*)&DriverObject->MajorFunction[i];
		myDbgPrint("Major Function Number : %d, %p", i, MjFunc);
		if (i == IRP_MJ_DEVICE_CONTROL) {
		//	InterlockedExchangePointer(MjFunc, MyDispatchIoctlDBVM);
		}
	}
	
	obfDereferenceObject(DriverObject);
	myDbgPrint("%ls", end);
	
	// my code end
	//////////////////////////////

	return;
}


extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT Driverobject, PUNICODE_STRING)
{

	// Change per PIS
	USHORT returnedDataMaxSize = sizeof(ULONG);

	ULONG* returnedDataAddress = (ULONG*)::ExAllocatePoolWithTag(NonPagedPool, returnedDataMaxSize, DRIVER_TAG);
	if (NULL == returnedDataAddress) {
		KdPrint((DRIVER_PREFIX "[-] Error allocating returned data space\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	DbgPrint("%ls", Driverobject->DriverName.Buffer);

	KernelPisParameters pisParameters;
	pisParameters.MmGetSystemRoutineAddress = MmGetSystemRoutineAddress;
	pisParameters.ReturnedDataAddress = returnedDataAddress;
	pisParameters.ReturnedDataMaxSize = returnedDataMaxSize;

	HANDLE threadHandle;
	auto status = ::PsCreateSystemThread(
		&threadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		NULL,
		NULL,
		PicStart,
		&pisParameters);
	if (!NT_SUCCESS(status))
		return status;

	PVOID threadObject;
	status = ::ObReferenceObjectByHandle(
		threadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		&threadObject,
		NULL);
	if (!NT_SUCCESS(status))
		return status;

	status = ::KeWaitForSingleObject(
		threadObject,
		Executive,
		KernelMode,
		FALSE,
		NULL);
	if (!NT_SUCCESS(status))
		return status;

	// Change per PIS
	KdPrint((DRIVER_PREFIX "PIS data returned: %d", *returnedDataAddress));

	::ExFreePoolWithTag(returnedDataAddress, DRIVER_TAG);

	return STATUS_SUCCESS;
}