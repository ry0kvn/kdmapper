#pragma once
#include "utils.hpp"
#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string.h>
#include "ce_driver.hpp"
#include "utils.hpp"
#include "Kernelmoduleunloader_resource.hpp"
#include "Kernelmoduleunloader_sig_resource.hpp"
#include "shellcode_resource.hpp"
#include "kernel_mode_shellcode_resource.hpp"
#include "kernel_mode_shellcode_ioctl_resource.hpp"
#include "portable_executable.hpp"
#include "ce_driver.hpp"


#define IOCTL_UNKNOWN_BASE					FILE_DEVICE_UNKNOWN
#define IOCTL_ALLOCATEMEM_NONPAGED    CTL_CODE(IOCTL_UNKNOWN_BASE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MAP_MEMORY						CTL_CODE(IOCTL_UNKNOWN_BASE, 0x084d, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_GETPROCADDRESS		CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0802, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_CREATE_DRIVER		CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0806, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_UNMAP_MEMORY					CTL_CODE(IOCTL_UNKNOWN_BASE, 0x084e, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_EXECUTE_CODE					CTL_CODE(IOCTL_UNKNOWN_BASE, 0x083c, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)


namespace kdmapper_ce {
	
	struct KernelPisParameters
	{
		LPVOID MmGetSystemRoutineAddress;
		LPVOID HookFunctionAddress;
		USHORT dummy;
	};

	extern PVOID64 pMmGetSystemRoutineAddress;
	extern PVOID64 pIofCompleteRequest;

	HANDLE GetDbk64DeviceHandleByInjection(HANDLE);
	HANDLE GetDbk64DeviceHandle();
	BOOL MapDriver(HANDLE, HANDLE, NTSTATUS*);
	BOOL PatchMajorFunction(HANDLE);
	BOOL ResolveImports(HANDLE hDevice, portable_executable::vec_imports imports);
	PVOID Dbk64HookedDeviceIoControlTest(HANDLE, PCWSTR);
	UINT64 AllocateNonPagedMem(HANDLE hDevice, SIZE_T Size);
	BOOL CreateSharedMemory(HANDLE hDevice, UINT64 kernelBuf, UINT64* sharedBuf, UINT64* Mdl, SIZE_T bufSize);
	BOOL UnMapSharedMemory(HANDLE hDevice, UINT64 sharedMemAddress, UINT64 Mdl);
	PVOID GetSystemProcAddress(HANDLE, PCWSTR);
	BOOL CreateDriverObject(HANDLE hDevice, UINT64 EntryPoint, PCWSTR driverName);
}