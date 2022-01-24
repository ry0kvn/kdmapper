#pragma once
#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <fstream>

#include "Kernelmoduleunloader_resource.hpp"

template <typename ... T>
void Error(const char* format, T const& ... args) {
	printf("[\x1b[31m!\x1b[39m] \x1b[41m");
	printf(format, args ...);
	printf("\x1b[49m\n");
}

template <typename ... T>
void Log(const char* format, T const& ... args) {
	printf("[\x1b[36m+\x1b[39m] ");
	printf(format, args ...);
	printf("\n");
}

template <typename ... T>
void Log2(const char* format, T const& ... args) {
#ifdef _DEBUG
	printf("[\x1b[32m*\x1b[39m] ");
	printf(format, args ...);
	printf("\n");
#endif // _DEBUG
	}

namespace utils {
	
	typedef struct _MEMORY_PATTERN {
		DWORD32 marks;
		DWORD32 handle;
		DWORD32 marks2;
	}MEMORY_PATTERN;

	std::wstring GetFullTempPath();
	bool CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size);
	void KdmapperInit();
	HANDLE ReadFileToMemory(const wchar_t* driver_name);
	bool CreateFileToTempFromResource(const wchar_t* file_name, const uint8_t resource_name[], size_t size);
	HANDLE CreateKernelModuleUnloaderProcess();
	LPVOID SearchProcessMemoryForPattern(HANDLE hProcess, MEMORY_PATTERN pattern, DWORD flProtect, DWORD flAllocationType, DWORD flType);
}