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

namespace kdmapper_ce {
	
	typedef struct _MEMORY_PATTERNS {
		DWORD32 marks;
		DWORD32 handle;
		DWORD32 marks2;
	}MEMORY_PATTERN;

	HANDLE CreateKernelModuleUnloaderProcess();
	HANDLE GetDbk64DeviceHandleByInjection(HANDLE);
	LPVOID SearchMemoryForPattern(HANDLE, MEMORY_PATTERN, DWORD, DWORD, DWORD);
	HANDLE GetDbk64DeviceHandle();
	BOOL MapDriver(HANDLE, HANDLE, NTSTATUS*);
}