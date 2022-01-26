#include "service.hpp"

bool service::RegisterAndStart(const std::wstring& driver_path) {

	const static DWORD ServiceTypeKernel = 1;
	const static DWORD dwType = SERVICE_DEMAND_START;
	const std::wstring servicesPath = L"SYSTEM\\ControlSet001\\Services\\" + ce_driver::GetDriverNameW();
	const std::wstring nPath = L"\\??\\" + driver_path;
	HKEY dservice;
	LSTATUS status;

	status = RegCreateKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &dservice); //Returns Ok if already exists
	
	if (status != ERROR_SUCCESS) {
		Error("Can't create service key");
		return false;
	}
	
	Log("Create service %ls", servicesPath.c_str());

	status = RegSetKeyValueW(dservice, NULL, L"ImagePath", REG_EXPAND_SZ, nPath.c_str(), (DWORD)(nPath.size() * sizeof(wchar_t)));
	
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Error("Can't create 'ImagePath' registry value");
		return false;
	}

	status = RegSetKeyValueW(dservice, NULL, L"Type", REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
	
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Error("Can't create 'Type' registry value");
		return false;
	}

	status = RegSetValueEx(dservice, L"Start", 0, REG_DWORD, (BYTE*)&dwType, sizeof(DWORD));
	
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Error("Can't create 'Type' registry value");
		return false;
	}

	// Initialize CheatEngine-specific registry.

	const std::wstring valeuA = L"\\Device\\" + ce_driver::GetDriverNameW(); // DeviceName
	const std::wstring valeuB = L"\\DosDevices\\" + ce_driver::GetDriverNameW(); // SymbolicLinkName
	const std::wstring valeuC = L"\\BaseNamedObjects\\dummy";
	const std::wstring valeuD = L"\\BaseNamedObjects\\dummy";

	status = RegSetKeyValueW(dservice, NULL, L"A", REG_SZ, (LPBYTE)valeuA.c_str(), (DWORD)(valeuA.size() * sizeof(wchar_t)));
	
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Error("Can't create 'Type' registry value");
		return false;
	}

	status = RegSetKeyValueW(dservice, NULL, L"B", REG_SZ, (LPBYTE)valeuB.c_str(), (DWORD)(valeuB.size() * sizeof(wchar_t)));
	
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Error("Can't create 'Type' registry value");
		return false;
	}
	
	status = RegSetKeyValueW(dservice, NULL, L"C", REG_SZ, (LPBYTE)valeuC.c_str(), (DWORD)(valeuC.size() * sizeof(wchar_t)));
	
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Error("Can't create 'Type' registry value");
		return false;
	}
	
	status = RegSetKeyValueW(dservice, NULL, L"D", REG_SZ, (LPBYTE)valeuD.c_str(), (DWORD)(valeuD.size() * sizeof(wchar_t)));
	
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Error("Can't create 'Type' registry value");
		return false;
	}

	RegCloseKey(dservice);

	HMODULE ntdll;
	ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;
	UNICODE_STRING serviceStr;
	std::wstring ServiceName = ce_driver::GetDriverNameW();

	ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) {
		return false;
	}

	auto RtlAdjustPrivilege = (pRtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
	auto NtLoadDriver = (pNtLoadDriver)GetProcAddress(ntdll, "NtLoadDriver");
	auto RtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");

	NTSTATUS Status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);

	if (!NT_SUCCESS(Status)) {
		Error("Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator.");
		return false;
	}

	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\ControlSet001\\Services\\" + ce_driver::GetDriverNameW();
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	Status = NtLoadDriver(&serviceStr);

	Log2("NtLoadDriver Status 0x%x", Status);

	Log("Successfully loaded the vulnerable driver");

	return true;
}

bool service::StopAndRemove(const std::wstring& driver_name) {

	HMODULE ntdll;
	UNICODE_STRING serviceStr;
	HKEY driver_service;
	LSTATUS status;
	std::wstring servicesPath = L"SYSTEM\\ControlSet001\\Services\\" + ce_driver::GetDriverNameW();

	ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL)
		return false;
	
	auto RtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
	auto NtUnloadDriver = (pNtUnloadDriver)GetProcAddress(ntdll, "NtUnloadDriver");

	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\ControlSet001\\Services\\" + ce_driver::GetDriverNameW();

	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	status = RegOpenKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &driver_service);
	
	if (status != ERROR_SUCCESS) {
		if (status == ERROR_FILE_NOT_FOUND) {
			return true;
		}
		return false;
	}
	
	RegCloseKey(driver_service);

	auto st = (NTSTATUS)NtUnloadDriver(&serviceStr);

	if (st != 0x0) {

		Log2("NtUnloadDriver Status 0x%x", st);

		Error("Driver Unload Failed!!");
		status = RegDeleteKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		return false; //lets consider unload fail as error because can cause problems with anti cheats later
	}


	status = RegDeleteKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str());

	if (status != ERROR_SUCCESS) {
		return false;
	}

	Log("Successfully unloaded the vulnerable driver");
	
	return true;
}
