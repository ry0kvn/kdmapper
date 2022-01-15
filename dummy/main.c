// Refs: https://github.com/hfiref0x/TDL/tree/master/Source/DummyDrv2/dummy 
#include <ntddk.h>
NTKERNELAPI
NTSTATUS
IoCreateDriver(
	IN PUNICODE_STRING DriverName, OPTIONAL
	IN PDRIVER_INITIALIZE InitializationFunction
);

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH DevioctlDispatch;
_Dispatch_type_(IRP_MJ_CREATE)
DRIVER_DISPATCH CreateDispatch;
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH CloseDispatch;

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CREATE_NAMED_PIPE)
_Dispatch_type_(IRP_MJ_CLOSE)
_Dispatch_type_(IRP_MJ_READ)
_Dispatch_type_(IRP_MJ_WRITE)
_Dispatch_type_(IRP_MJ_QUERY_INFORMATION)
_Dispatch_type_(IRP_MJ_SET_INFORMATION)
_Dispatch_type_(IRP_MJ_QUERY_EA)
_Dispatch_type_(IRP_MJ_SET_EA)
_Dispatch_type_(IRP_MJ_FLUSH_BUFFERS)
_Dispatch_type_(IRP_MJ_QUERY_VOLUME_INFORMATION)
_Dispatch_type_(IRP_MJ_SET_VOLUME_INFORMATION)
_Dispatch_type_(IRP_MJ_DIRECTORY_CONTROL)
_Dispatch_type_(IRP_MJ_FILE_SYSTEM_CONTROL)
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
_Dispatch_type_(IRP_MJ_INTERNAL_DEVICE_CONTROL)
_Dispatch_type_(IRP_MJ_SHUTDOWN)
_Dispatch_type_(IRP_MJ_LOCK_CONTROL)
_Dispatch_type_(IRP_MJ_CLEANUP)
_Dispatch_type_(IRP_MJ_CREATE_MAILSLOT)
_Dispatch_type_(IRP_MJ_QUERY_SECURITY)
_Dispatch_type_(IRP_MJ_SET_SECURITY)
_Dispatch_type_(IRP_MJ_POWER)
_Dispatch_type_(IRP_MJ_SYSTEM_CONTROL)
_Dispatch_type_(IRP_MJ_DEVICE_CHANGE)
_Dispatch_type_(IRP_MJ_QUERY_QUOTA)
_Dispatch_type_(IRP_MJ_SET_QUOTA)
_Dispatch_type_(IRP_MJ_PNP)
DRIVER_DISPATCH UnsupportedDispatch;

DRIVER_INITIALIZE DriverInitialize;
DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text(INIT, DriverEntry)

#define DUMMYDRV_REQUEST1    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0701, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _INOUT_PARAM {
	ULONG Param1;
	ULONG Param2;
	ULONG Param3;
	ULONG Param4;
} INOUT_PARAM, * PINOUTPARAM;
#define DEBUGPRINT

/*
* PrintIrql
*
* Purpose:
*
* Debug print current irql.
*
*/
VOID PrintIrql()
{
	KIRQL Irql;
	PWSTR sIrql;

	Irql = KeGetCurrentIrql();

	switch (Irql) {

	case PASSIVE_LEVEL:
		sIrql = L"PASSIVE_LEVEL";
		break;
	case APC_LEVEL:
		sIrql = L"APC_LEVEL";
		break;
	case DISPATCH_LEVEL:
		sIrql = L"DISPATCH_LEVEL";
		break;
	case CMCI_LEVEL:
		sIrql = L"CMCI_LEVEL";
		break;
	case CLOCK_LEVEL:
		sIrql = L"CLOCK_LEVEL";
		break;
	case IPI_LEVEL:
		sIrql = L"IPI_LEVEL";
		break;
	case HIGH_LEVEL:
		sIrql = L"HIGH_LEVEL";
		break;
	default:
		sIrql = L"Unknown Value";
		break;
	}
	DbgPrint("KeGetCurrentIrql=%u(%ws)\n", Irql, sIrql);
}

/*
* DevioctlDispatch
*
* Purpose:
*
* IRP_MJ_DEVICE_CONTROL dispatch.
*
*/
NTSTATUS DevioctlDispatch(
	_In_ struct _DEVICE_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp
)
{
	NTSTATUS				status = STATUS_SUCCESS;
	ULONG					bytesIO = 0;
	PIO_STACK_LOCATION		stack;
	BOOLEAN					condition = FALSE;
	PINOUTPARAM             rp, wp;

	UNREFERENCED_PARAMETER(DeviceObject);

#ifdef DEBUGPRINT
	DbgPrint("%s IRP_MJ_DEVICE_CONTROL", __FUNCTION__);
#endif

	stack = IoGetCurrentIrpStackLocation(Irp);

	do {

		if (stack == NULL) {
			status = STATUS_INTERNAL_ERROR;
			break;
		}

		rp = (PINOUTPARAM)Irp->AssociatedIrp.SystemBuffer;
		wp = (PINOUTPARAM)Irp->AssociatedIrp.SystemBuffer;
		if (rp == NULL) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		switch (stack->Parameters.DeviceIoControl.IoControlCode) {
		case DUMMYDRV_REQUEST1:

#ifdef DEBUGPRINT
			DbgPrint("%s DUMMYDRV_REQUEST1 hit", __FUNCTION__);
#endif			
			if (stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(INOUT_PARAM)) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

#ifdef DEBUGPRINT
			DbgPrint("%s in params = %lx, %lx, %lx, %lx", __FUNCTION__,
				rp->Param1, rp->Param2, rp->Param3, rp->Param4);
#endif

			wp->Param1 = 11111111;
			wp->Param2 = 22222222;
			wp->Param3 = 33333333;
			wp->Param4 = 44444444;

			status = STATUS_SUCCESS;
			bytesIO = sizeof(INOUT_PARAM);

			break;

		default:

#ifdef DEBUGPRINT
			DbgPrint("%s hit with invalid IoControlCode", __FUNCTION__);
#endif
			status = STATUS_INVALID_PARAMETER;
		};

	} while (condition);

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = bytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

/*
* UnsupportedDispatch
*
* Purpose:
*
* Unused IRP_MJ_* dispatch.
*
*/
NTSTATUS UnsupportedDispatch(
	_In_ struct _DEVICE_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

/*
* CreateDispatch
*
* Purpose:
*
* IRP_MJ_CREATE dispatch.
*
*/
NTSTATUS CreateDispatch(
	_In_ struct _DEVICE_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

#ifdef DEBUGPRINT
	DbgPrint("%s Create", __FUNCTION__);
#endif

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

/*
* CloseDispatch
*
* Purpose:
*
* IRP_MJ_CLOSE dispatch.
*
*/
NTSTATUS CloseDispatch(
	_In_ struct _DEVICE_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

#ifdef DEBUGPRINT
	DbgPrint("%s Close", __FUNCTION__);
#endif

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

/*
* DriverInitialize
*
* Purpose:
*
* Driver main.
*
*/
NTSTATUS DriverInitialize(
	_In_  struct _DRIVER_OBJECT* DriverObject,
	_In_  PUNICODE_STRING RegistryPath
)
{
	NTSTATUS        status;
	UNICODE_STRING  SymLink, DevName;
	PDEVICE_OBJECT  devobj;
	ULONG           t;

	//RegistryPath is NULL
	UNREFERENCED_PARAMETER(RegistryPath);

#ifdef DEBUGPRINT
	DbgPrint("%s\n", __FUNCTION__);
#endif

	RtlInitUnicodeString(&DevName, L"\\Device\\TDLD");
	status = IoCreateDevice(DriverObject, 0, &DevName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &devobj);

#ifdef DEBUGPRINT
	DbgPrint("%s IoCreateDevice(%wZ) = %lx\n", __FUNCTION__, DevName, status);
#endif

	if (!NT_SUCCESS(status)) {
		return status;
	}

	RtlInitUnicodeString(&SymLink, L"\\DosDevices\\TDLD");
	status = IoCreateSymbolicLink(&SymLink, &DevName);

#ifdef DEBUGPRINT
	DbgPrint("%s IoCreateSymbolicLink(%wZ) = %lx\n", __FUNCTION__, SymLink, status);
#endif

	devobj->Flags |= DO_BUFFERED_IO;

	for (t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
		DriverObject->MajorFunction[t] = &UnsupportedDispatch;

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &DevioctlDispatch;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = &CreateDispatch;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = &CloseDispatch;
	DriverObject->DriverUnload = NULL; //nonstandard way of driver loading, no unload

	devobj->Flags &= ~DO_DEVICE_INITIALIZING;
	return status;
}

/*
* DriverEntry
*
* Purpose:
*
* Driver base entry point.
*
*/
NTSTATUS DriverEntry(
	_In_  struct _DRIVER_OBJECT* DriverObject,
	_In_  PUNICODE_STRING RegistryPath
)
{
	NTSTATUS        status = STATUS_SUCCESS;
	DriverInitialize(DriverObject, RegistryPath);
	return status;
}
