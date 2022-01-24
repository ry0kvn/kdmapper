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

bool utils::CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size) {
	
	std::ofstream file_ofstream(desired_file_path.c_str(), std::ios_base::out | std::ios_base::binary);

	_wremove(desired_file_path.c_str());

	if (!file_ofstream.write(address, size)) {
		file_ofstream.close();
		return false;
	}

	file_ofstream.close();
	return true;
}

std::wstring utils::GetFullTempPath() {
	wchar_t temp_directory[MAX_PATH + 1] = { 0 };
	const uint32_t get_temp_path_ret = GetTempPathW(sizeof(temp_directory) / 2, temp_directory);
	if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH + 1) {
		Log("Failed to get temp path");
		return L"";
	}
	if (temp_directory[wcslen(temp_directory) - 1] == L'\\')
		temp_directory[wcslen(temp_directory) - 1] = 0x0;

	return std::wstring(temp_directory);
}

HANDLE utils::ReadFileToMemory(const wchar_t* DriverName) {
	// TODO: ifstreamégÇ¡ÇƒèëÇ´íºÇµ
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

bool utils::CreateFileToTempFromResource(const wchar_t* file_name, const uint8_t resource_name[], size_t size) {
	
	std::wstring SigFilePath = utils::GetFullTempPath() + L"\\" + file_name;
	
	_wremove(SigFilePath.c_str());

	if (!utils::CreateFileFromMemory(SigFilePath, reinterpret_cast<const char*>(resource_name), size)) {
		Error("Failed to create file");
		return false;
	}

	return true;
}


HANDLE utils::CreateKernelModuleUnloaderProcess() {

	HANDLE result = INVALID_HANDLE_VALUE;

	// drop kernelmoduleunloader.exe into the %temp% folder

	std::wstring UnloaderPath = utils::GetFullTempPath() + L"\\" + L"Kernelmoduleunloader.exe";
	utils::CreateFileToTempFromResource(L"Kernelmoduleunloader.exe", kernelmoduleunloader_resource::kernelmoduleunloader, sizeof(kernelmoduleunloader_resource::kernelmoduleunloader));


	// adjust process token

	BOOL bRet = FALSE;
	HANDLE hToken = NULL;
	LUID luid = { 0 };

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
		{
			TOKEN_PRIVILEGES tokenPriv = { 0 };
			tokenPriv.PrivilegeCount = 1;
			tokenPriv.Privileges[0].Luid = luid;
			tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			bRet = AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
		}
	}
	if (!bRet) {
		Error("RtlAdjustPrivilege failed");
		return result;
	}

	// spawn kernelmoduleunloader.exe process
	// TODO: hide kernelmoduleunloader's popup

	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcess(NULL,
		(LPWSTR)UnloaderPath.c_str(),
		NULL,
		NULL,
		TRUE,          // bInheritHandles: Because shellcode requires SE_PRIVILEGE_ENABLED
		CREATE_NO_WINDOW,
		NULL,
		NULL,
		&si,
		&pi))
	{
		Error("CreateProcess failed 0x%x", GetLastError());
		return result;
	}

	result = pi.hProcess;
	//CloseHandle(pi.hThread);
	//CloseHandle(pi.hProcess);
	return result;
}

LPVOID utils::SearchProcessMemoryForPattern(HANDLE hProcess, MEMORY_PATTERN pattern, DWORD flProtect, DWORD flAllocationType, DWORD flType) {

	LPVOID offset = 0;
	LPVOID lpBuffer = NULL;
	MEMORY_BASIC_INFORMATION mbi = {};

	lpBuffer = VirtualAlloc(NULL, sizeof(MEMORY_PATTERN), MEM_COMMIT, PAGE_READWRITE);
	if (lpBuffer == NULL) {
		Error("VirtualAlloc failed");
		return NULL;
	}

#ifdef _DEBUG
	//printf("BaseAddress");
	//printf("\tRegionSize");
	//printf("\tProtect");
	//printf("\tState");
	//printf("\tType\n");
#endif // _DEBUG

	while (VirtualQueryEx(hProcess, offset, &mbi, sizeof(mbi)))
	{

#ifdef _DEBUG
		//printf("0x%llx", mbi.BaseAddress);
		//printf("\t%llx", mbi.RegionSize);
		//printf("\t%lx", mbi.AllocationProtect);
		//printf("\t%lx", mbi.State);
		//printf("\t%lx\n", mbi.Type);
#endif // _DEBUG

		// Compare patterns

		ReadProcessMemory(hProcess, mbi.BaseAddress, lpBuffer, sizeof(MEMORY_PATTERN), NULL);
		SIZE_T res = RtlCompareMemory(lpBuffer, (const void*)&pattern, sizeof(MEMORY_PATTERN));

		if (mbi.AllocationProtect == flProtect && mbi.State == flAllocationType && mbi.Type == flType && res != (SIZE_T)0)
		{

			res = RtlCompareMemory((LPVOID)((UINT64)lpBuffer + (UINT64)0x8), (const void*)&pattern, sizeof(MEMORY_PATTERN));

			if (mbi.AllocationProtect == flProtect && mbi.State == flAllocationType && mbi.Type == flType && res != (SIZE_T)0)
			{
				Log("Pattern found at 0x%x (match pattern count: 0x%d)", mbi.BaseAddress, res);
				break;
			}
		}

		if (mbi.BaseAddress > (PVOID)0x7fffffff)
		{
			Error("Scan error: No pattern found");
			break;
		}

		offset = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
	}

	return lpBuffer;
}