#pragma once
#include <Windows.h>
#include <stdio.h>

template <typename ... T>
void Error(const char* format, T const& ... args) {
	printf("[\x1b[31m-\x1b[39m] \x1b[41m");
	printf(format, args ...);
	printf("\x1b[49m\n");
}
template <typename ... T>
void Log(const char* format, T const& ... args) {
	printf("[\x1b[36m+\x1b[39m] ");
	printf(format, args ...);
	printf("\n");
}


namespace utils {
	void KdmapperInit();
	HANDLE ReadFileToMemory(const wchar_t* driver_name);
}