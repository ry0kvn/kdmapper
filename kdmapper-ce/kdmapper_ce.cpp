#include "kdmapper_ce.hpp"

HANDLE kdmapper_ce::GetDbk64DeviceHandle()
{
	HANDLE hDbk64 = INVALID_HANDLE_VALUE;
		
	// drop kernelmoduleunloader.exe into the %temp% folder
	std::wstring UnloaderPath = utils::GetFullTempPath() + L"\\" + L"Kernelmoduleunloader.exe";
	_wremove(UnloaderPath.c_str());

	// Kernelmoduleunloader.exe
	if (!utils::CreateFileFromMemory(UnloaderPath, reinterpret_cast<const char*>(kernelmoduleunloader_resource::kernelmoduleunloader), sizeof(kernelmoduleunloader_resource::kernelmoduleunloader))) {
		Log("Failed to create vulnerable driver file");
		return hDbk64;
	}

	// kernelmoduleunloaderÉvÉçÉZÉXÇçÏê¨

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
     
    // Start the child process. 
    //if (!CreateProcess(NULL,   // No module name (use command line)
    //    (LPWSTR)UnloaderPath.c_str(),        // Command line
    //    NULL,           // Process handle not inheritable
    //    NULL,           // Thread handle not inheritable
    //    FALSE,          // Set handle inheritance to FALSE
    //    CREATE_NO_WINDOW,              // No creation flags
    //    NULL,           // Use parent's environment block
    //    NULL,           // Use parent's starting directory 
    //    &si,            // Pointer to STARTUPINFO structure
    //    &pi)           // Pointer to PROCESS_INFORMATION structure
    //    )
    //{
    //    Error("CreateProcess failed 0x%x", GetLastError());
    //    return hDbk64;
    //}

    // TODO: hide kernelmoduleunloader's popup

	// inject shellcode
    struct handle_marks {
        DWORD marks;
        HANDLE handle;
    };
    handle_marks mhandle = {
        0x12345678,
        CreateFileW(L"\\\\.\\EvilCEDRIVER73", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)
    };
	// get dbk64.sys handle
	
   // TerminateProcess(pi.hProcess, 0);
    // Close process and thread handles. 
    //CloseHandle(pi.hProcess);
    //CloseHandle(pi.hThread);
	
    return hDbk64;
}
