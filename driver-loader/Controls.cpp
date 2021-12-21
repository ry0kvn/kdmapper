#pragma once
#include "Driver.hpp"

_Use_decl_annotations_
NTSTATUS ReflectiveLoaderDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	//KdPrint(("[+] ReflectiveLoaderDeviceControl Enter\n"));
	UNREFERENCED_PARAMETER(DeviceObject);

	auto irpStack = IoGetCurrentIrpStackLocation(Irp);
	auto ntStatus = STATUS_UNSUCCESSFUL;
	auto IoControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

	switch (IoControlCode) {
	
	case IOCTL_ALLOCATEMEM_NONPAGED:
	{
		KdPrint(("Entering IOCTL_ALLOCATEMEM_NONPAGED\n"));

		PVOID address;
		SIZE_T size;
		struct input{
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
		KdPrint(("Entering IOCTL_GETPROCADDRESS\n"));

		PVOID function_address;
		UNICODE_STRING function_name;
		UINT64 result;
		struct input{
			UINT64 function_name;
		}*inp = (input*)Irp->AssociatedIrp.SystemBuffer;
		
		RtlInitUnicodeString(&function_name, (PCWSTR)(UINT_PTR)(inp->function_name));
		function_address = MmGetSystemRoutineAddress(&function_name);

		if (function_address != NULL) {
			DbgPrint("MmGetSystemRoutineAddress solved %ls: %p\n", inp->function_name, function_address);
			result = (UINT64)function_address;
			ntStatus = STATUS_SUCCESS;
		}
		else {
			DbgPrint("MmGetSystemRoutineAddress failed %ls\n", (char*)inp->function_name);
			result = NULL;
			ntStatus = STATUS_UNSUCCESSFUL;
		}

		RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &result, 8);
		Irp->IoStatus.Information = sizeof UINT64;

		break;
	}

	case IOCTL_FREE_NONPAGED:
	{
		KdPrint(("Entering IOCTL_FREE_NONPAGED\n"));

		struct input{
			UINT64 Address;
		}*inp = (input*)Irp->AssociatedIrp.SystemBuffer;

		ExFreePool((PVOID)(UINT_PTR)inp->Address);
		ntStatus = STATUS_SUCCESS;
		DbgPrint("FreePool success. (addr = %p)", (void*)inp->Address);

		break;
	}

	case IOCTL_WRITEMEMORY:
	{
		KdPrint(("Entering IOCTL_WRITEMEMORY\n"));

		struct input{
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
		KdPrint(("Entering IOCTL_EXECUTE_CODE\n"));

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

	default:
		ntStatus = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	Irp->IoStatus.Status = ntStatus;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return ntStatus;
}
