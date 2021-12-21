#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include "ioctls.hpp"
#include "ReflectiveLoaderCommon.hpp"

NTSTATUS ReflectiveLoaderDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);