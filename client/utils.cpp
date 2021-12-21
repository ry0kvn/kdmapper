#include "utils.hpp"


bool utils::InstallDriver(const wchar_t* ServiceName, const wchar_t* DriverPath) {

	SC_HANDLE hSCManager;
	SC_HANDLE hService;

	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCManager == NULL)
		ErrorAndReturnZero("Failed hSCManager");

	hService = OpenService(hSCManager, ServiceName, SERVICE_ALL_ACCESS);
	if (hService == 0) {
		hService = CreateService(
			hSCManager,   // SCManager database
			ServiceName,  // name of service
			ServiceName, // name to display
			SERVICE_ALL_ACCESS,
			SERVICE_KERNEL_DRIVER,
			SERVICE_DEMAND_START,
			SERVICE_ERROR_NORMAL,
			DriverPath,
			NULL, NULL, NULL, NULL, NULL);

		if (hService == NULL) {
			CloseServiceHandle(hSCManager);
			ErrorAndReturnZero("Failed CreateService")
		}
	}

	if (StartService(hService, 0, NULL) == FALSE) {
		DWORD dwError = GetLastError();
		if (dwError != ERROR_SERVICE_ALREADY_RUNNING) {
			DeleteService(hService);
			CloseServiceHandle(hService);
			CloseServiceHandle(hSCManager);

			ErrorAndReturnZero("Failed StartService");
		}
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	return TRUE;

}

bool utils::UninstallDriver(const wchar_t* ServiceName) {

	SC_HANDLE hSCManager;
	SC_HANDLE       hService;
	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCManager == NULL)
		ErrorAndReturnZero("Failed OpenSCManager");

	hService = OpenService(hSCManager, ServiceName, SERVICE_ALL_ACCESS);
	if (hService == 0) {
		CloseServiceHandle(hSCManager);
		ErrorAndReturnZero("Failed OpenService");
	}

	SERVICE_STATUS status;
	ControlService(hService, SERVICE_CONTROL_STOP, &status);
	DeleteService(hService);

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);

	return TRUE;

}


bool utils::ScanParam(int argc, wchar_t* argv[]) {
	//for (int i = 0; i < argc; i++) {
	//    printf("[debug] %ls\n", argv[i]);
	//}

	if (argc < 2)
		ErrorAndReturnZero("param error");

	return TRUE;
}


HANDLE utils::ReadFileToMemory(const wchar_t* driver_name) {

	HANDLE hFile = CreateFile(
		driver_name,
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
	Log("%ls (%d bytes)", driver_name, FileSize);

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

bool utils::RegisterAndStartLoaderService(const wchar_t* ServiceName, const wchar_t* DriverPath) {

	if (!InstallDriver(ServiceName, DriverPath)) {
		UninstallDriver(ServiceName);
		return FALSE;
	}
	return TRUE;

}

uint64_t utils::GetKernelModuleAddress(const std::string& module_name) {
	void* buffer = nullptr;
	DWORD buffer_size = 0;

	NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);

	while (status == nt::STATUS_INFO_LENGTH_MISMATCH) {
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);

		buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);
	}

	if (!NT_SUCCESS(status)) {
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);
		return 0;
	}

	const auto modules = static_cast<nt::PRTL_PROCESS_MODULES>(buffer);
	if (!modules)
		return 0;

	for (auto i = 0u; i < modules->NumberOfModules; ++i) {
		const std::string current_module_name = std::string(reinterpret_cast<char*>(modules->Modules[i].FullPathName) + modules->Modules[i].OffsetToFileName);

		if (!_stricmp(current_module_name.c_str(), module_name.c_str()))
		{
			const uint64_t result = reinterpret_cast<uint64_t>(modules->Modules[i].ImageBase);

			VirtualFree(buffer, 0, MEM_RELEASE);
			return result;
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);
	return 0;
}
