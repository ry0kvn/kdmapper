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

#define IOCTL_UNKNOWN_BASE					FILE_DEVICE_UNKNOWN
#define IOCTL_CE_TEST							CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0804, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_ALLOCATEMEM_NONPAGED			CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0826, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_GETPROCADDRESS					CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0827, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_MAP_MEMORY						CTL_CODE(IOCTL_UNKNOWN_BASE, 0x084d, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_UNMAP_MEMORY					CTL_CODE(IOCTL_UNKNOWN_BASE, 0x084e, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_EXECUTE_CODE					CTL_CODE(IOCTL_UNKNOWN_BASE, 0x083c, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)


namespace kdmapper_ce {

	typedef struct _MEMORY_PATTERN {
		DWORD32 marks;
		DWORD32 handle;
		DWORD32 marks2;
	}MEMORY_PATTERN;

	HANDLE CreateKernelModuleUnloaderProcess();
	HANDLE GetDbk64DeviceHandleByInjection(HANDLE);
	LPVOID SearchMemoryForPattern(HANDLE, MEMORY_PATTERN, DWORD, DWORD, DWORD);
	HANDLE GetDbk64DeviceHandle();
	BOOL MapDriver(HANDLE, HANDLE, NTSTATUS*);
	UINT64 AllocateNonPagedMem(HANDLE, SIZE_T);
	BOOL CreateSharedMemory(HANDLE, UINT64, UINT64*, UINT64*, SIZE_T);
	BOOL UnMapSharedMemory(HANDLE, UINT64, UINT64);
	BOOL ExecuteKernelModeShellCode(HANDLE, UINT64, UINT64);
	BOOL Dbk64DeviceIoControlTest(HANDLE);
	PVOID GetSystemProcAddress(HANDLE, PCWSTR);
	BOOL PatchMajorFunction(HANDLE);
}