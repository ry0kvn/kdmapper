#pragma once
#include <Windows.h>
#include <stdio.h>
#include "iostream"
#include "utils.hpp"
#include "nt.hpp"
#include "portable_executable.hpp"
#include "../driver-loader/ReflectiveLoaderCommon.hpp"
#include "../driver-loader/ioctls.hpp"


#define LOADER_DRIVER_NAME L"reflective-driver-loader.sys"
#define LOADER_SERVICE_NAME  L"ReflectiveLoader"

bool ReflectiveLoad(const HANDLE);
void RelocateImageByDelta(portable_executable::vec_relocs relocs, const uint64_t delta);
uint64_t AllocatePool(HANDLE, SIZE_T);
bool FreePool(HANDLE hDevice, UINT64 address);
uint64_t GetKernelModuleExport(HANDLE hDevice, uint64_t kernel_module_base, const std::string& function_name);
bool ResolveImports(HANDLE hDevice, portable_executable::vec_imports imports);
bool ReadMemory(HANDLE hDevice, uint64_t address, void* buffer, uint64_t size);
uint64_t MmGetSystemRoutineAddress(HANDLE hDevice, std::string function_name);
bool WriteMemory(HANDLE hDevice, uint64_t address, void* buffer, uint64_t size);
bool CallDriverEntry(HANDLE hDevice, UINT64 EntryPoint);

ULONG64 ntoskrnlAddr = 0;


