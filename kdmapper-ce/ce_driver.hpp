#pragma once
#include <Windows.h>
#include <stdio.h>
#include <string>
#include <time.h>

#include "utils.hpp"
#include "service.hpp"

#if _DEBUG

#include "test_dbk64_driver_resource.hpp"

#else

#include "dbk64_driver_resource.hpp"

#endif

#define IOCTL_UNKNOWN_BASE					FILE_DEVICE_UNKNOWN
#define IOCTL_CE_TEST							CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0804, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_ALLOCATEMEM_NONPAGED			CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0826, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_GETPROCADDRESS					CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0827, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_EXECUTE_CODE					CTL_CODE(IOCTL_UNKNOWN_BASE, 0x083c, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_MAP_MEMORY						CTL_CODE(IOCTL_UNKNOWN_BASE, 0x084d, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_UNMAP_MEMORY					CTL_CODE(IOCTL_UNKNOWN_BASE, 0x084e, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

namespace ce_driver {
	extern char driver_name[100] ; // dbk64.sys

	std::wstring GetDriverNameW();
	std::wstring GetDriverPath();
	BOOL Load();

	// IOCTLs
	UINT64 AllocateNonPagedMem(HANDLE, SIZE_T);
	BOOL CreateSharedMemory(HANDLE, UINT64, UINT64*, UINT64* , SIZE_T);
	BOOL UnMapSharedMemory(HANDLE, UINT64, UINT64);
	BOOL ExecuteKernelModeShellCode(HANDLE, UINT64, UINT64);
	PVOID64 GetSystemProcAddress(HANDLE, PCWSTR);
	BOOL Dbk64DeviceIoControlTest(HANDLE);
	bool CallDriverEntry(HANDLE hDevice, UINT64 EntryPoint);
	PVOID64 WriteNonPagedMemory(HANDLE hDevice, PVOID lpBuffer, SIZE_T nSize);
}