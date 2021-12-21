#include <Windows.h>
#include <TlHelp32.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>

#include "nt.hpp"

#define ErrorAndReturnZero(content) {printf("[-] %s (error code = %d)\n", content, GetLastError()); return 0;}
#define ErrorAndBreak(content) {printf("[-] %s (error code = %d)\n", content, GetLastError()); break;}
#define Error(content) {printf("[-] %s (error code = %d)\n", content, GetLastError());}

template <typename ... T>
__forceinline void Log(const char* format, T const& ... args)
{
	printf("[+] ");
	printf(format, args ... );
	printf("\n");
}

namespace utils {
	bool InstallDriver(const wchar_t* ServiceName, const wchar_t* DriverPath);
	bool UninstallDriver(const wchar_t* ServiceName);
	bool ScanParam(int argc, wchar_t* argv[]);
	HANDLE ReadFileToMemory(const wchar_t* driver_name);
	bool RegisterAndStartLoaderService(const wchar_t* ServiceName, const wchar_t* DriverPath);
	uint64_t GetKernelModuleAddress(const std::string& module_name);
}

