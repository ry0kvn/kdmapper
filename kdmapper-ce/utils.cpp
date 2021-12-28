#include "utils.hpp"


void utils::KdmapperInit()
{
	// Enable escape sequence
	HANDLE stdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD consoleMode = 0;
	GetConsoleMode(stdOut, &consoleMode);
	consoleMode = consoleMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	SetConsoleMode(stdOut, consoleMode);
}

HANDLE utils::ReadFileToMemory(const wchar_t* DriverName) {

	HANDLE hFile = CreateFile(
		DriverName,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		Error("CreateFile Failed");
		return INVALID_HANDLE_VALUE;
	}

	DWORD FileSize = GetFileSize(hFile, NULL);
	Log("Input Driver: %ls (%d bytes)", DriverName, FileSize);

	HANDLE* hImage = (HANDLE*)VirtualAlloc(NULL, FileSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	bool bRet = ReadFile(hFile, hImage, FileSize, NULL, NULL);

	if (!bRet) {
		CloseHandle(hFile);
		Error("ReadFile Failed");
		return INVALID_HANDLE_VALUE;
	}

	CloseHandle(hFile);
	return hImage;
}