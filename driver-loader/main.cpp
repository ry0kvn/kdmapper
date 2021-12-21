#include "Driver.hpp"
#include "Controls.hpp"

// DriverEntry
extern "C" NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	DbgPrint("[+] ReflectiveLoader DriverEntry started\n");

	DriverObject->DriverUnload = Unload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ReflectiveLoaderDeviceControl;

	UNICODE_STRING devName = RTL_CONSTANT_STRING(RL_DEVICE_NAME);	
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(RL_SYM_NAME);
	PDEVICE_OBJECT DeviceObject = nullptr;
	auto status = STATUS_SUCCESS;
	auto symLinkCreated = false;

	do {

		status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
		if (!NT_SUCCESS(status)) {
			DbgPrint("Failed to create device (0x%08X)\n", status);
			break;
		}

		DriverObject->DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
		DriverObject->DeviceObject->Flags |= DO_BUFFERED_IO;

		status = IoCreateSymbolicLink(&symLink, &devName);
		if (!NT_SUCCESS(status)) {
			DbgPrint("Failed to create symbolic link (0x%08X)\n", status);
			break;
		}
		symLinkCreated = true;

	} while (false);


	if (!NT_SUCCESS(status)) {
		if (symLinkCreated)
			IoDeleteSymbolicLink(&symLink);
		if (DeviceObject)
			IoDeleteDevice(DeviceObject);
	}

	DbgPrint(("[+] ReflectiveLoader DriverEntry completed successfully\n"));
	return STATUS_SUCCESS;
}

_Use_decl_annotations_
void Unload(_In_ PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(RL_SYM_NAME);
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);
	DbgPrint(("[+] ReflectiveLoader unloaded\n"));
}

_Use_decl_annotations_
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	DbgPrint(("[+] ReflectiveLoader CreateClose enter\n"));

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}