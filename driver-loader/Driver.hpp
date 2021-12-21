#pragma once
#pragma warning(disable :4456 4996)
#include <ntifs.h>
#include <ntddk.h>
#include "ioctls.hpp"
#include "ReflectiveLoaderCommon.hpp"

void Unload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS CreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
