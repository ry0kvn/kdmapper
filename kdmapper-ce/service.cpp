#include "service.hpp"

bool service::RegisterAndStart(const std::wstring& driver_path) {
	const static DWORD ServiceTypeKernel = 1;
	//const std::wstring driver_name = L"mydbk64";
	//const std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + driver_name;
	const std::wstring servicesPath = L"SYSTEM\\ControlSet001\\Services\\" +ce_driver::GetDriverNameW();
	const std::wstring nPath = L"\\??\\" + driver_path;

	HKEY dservice;
	LSTATUS status = RegCreateKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &dservice); //Returns Ok if already exists
	if (status != ERROR_SUCCESS) {
		Log("[-] Can't create service key");
		return false;
	}
	Log("Create service %ls", servicesPath.c_str());

	status = RegSetKeyValueW(dservice, NULL, L"ImagePath", REG_EXPAND_SZ, nPath.c_str(), (DWORD)(nPath.size() * sizeof(wchar_t)));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Log("[-] Can't create 'ImagePath' registry value");
		return false;
	}

	status = RegSetKeyValueW(dservice, NULL, L"Type", REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Log("[-] Can't create 'Type' registry value");
		return false;
	}

	const static DWORD dwType = SERVICE_DEMAND_START;
	status = RegSetValueEx(dservice, L"Start", 0, REG_DWORD, (BYTE*)&dwType, sizeof(DWORD));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Log("[-] Can't create 'Type' registry value");
		return false;
	}

	// TODO: ÉåÉWÉXÉgÉäèâä˙âªèàóùÇÕservice.cppÇ∆ce_driver.cppÇ≈ï™ÇØÇÈ
	/////////////////////////////////////////
	// Initialize CheatEngine-specific registry.
	// https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/NtLoadDriver-C%2B%2B.cpp
	// https://fullpwnops.com/NtLoadDriver/	
	const std::wstring valeuA = L"\\Device\\EvilCEDRIVER73"; // DeviceName
	const std::wstring valeuB = L"\\DosDevices\\EvilCEDRIVER73"; // SymbolicLinkName
	const std::wstring valeuC = L"\\BaseNamedObjects\\DBKProcList60";
	const std::wstring valeuD = L"\\BaseNamedObjects\\DBKThreadList60";

	status = RegSetKeyValueW(dservice, NULL, L"A", REG_SZ, (LPBYTE)valeuA.c_str(), (DWORD)(valeuA.size() * sizeof(wchar_t)));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Log("[-] Can't create 'Type' registry value");
		return false;
	}
	status = RegSetKeyValueW(dservice, NULL, L"B", REG_SZ, (LPBYTE)valeuB.c_str(), (DWORD)(valeuB.size() * sizeof(wchar_t)));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Log("[-] Can't create 'Type' registry value");
		return false;
	}
	status = RegSetKeyValueW(dservice, NULL, L"C", REG_SZ, (LPBYTE)valeuC.c_str(), (DWORD)(valeuC.size() * sizeof(wchar_t)));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Log("[-] Can't create 'Type' registry value");
		return false;
	}
	status = RegSetKeyValueW(dservice, NULL, L"D", REG_SZ, (LPBYTE)valeuD.c_str(), (DWORD)(valeuD.size() * sizeof(wchar_t)));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Log("[-] Can't create 'Type' registry value");
		return false;
	}
	/////////////////////////////////////////

	RegCloseKey(dservice);

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) {
		return false;
	}

	typedef NTSTATUS(*myRtlAdjustPrivilege)(_In_ ULONG Privilege, _In_ BOOLEAN Enable, _In_ BOOLEAN Client, _Out_ PBOOLEAN WasEnabled);
	myRtlAdjustPrivilege RtlAdjustPrivilege = (myRtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");

	ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;
	NTSTATUS Status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
	if (!NT_SUCCESS(Status)) {
		Log("Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator.");
		return false;
	}
	std::wstring ServiceName = ce_driver::GetDriverNameW();

	// TODO: fix
	typedef NTSTATUS(*myNtLoadDriver)(_In_ PUNICODE_STRING DriverServiceName);
	auto NtLoadDriver = (myNtLoadDriver)GetProcAddress(ntdll, "NtLoadDriver");

	typedef VOID(*myRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
	auto RtlInitUnicodeString = (myRtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\ControlSet001\\Services\\" + ce_driver::GetDriverNameW();
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	Status = NtLoadDriver(&serviceStr);
#ifdef _DEBUG
	Log("NtLoadDriver Status 0x%x", Status);
#endif // DEBUG

	//Never should occur since kdmapper checks for "IsRunning" driver before
	if (Status == 0xC000010E) {// STATUS_IMAGE_ALREADY_LOADED
		Log("Successfully loaded the vulnerable driver");
		return true;
	}

	Log("Successfully loaded the vulnerable driver");
	return true;
}

bool service::StopAndRemove(const std::wstring& driver_name) {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL)
		return false;
	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\ControlSet001\\Services\\" + ce_driver::GetDriverNameW();
	UNICODE_STRING serviceStr;

	typedef VOID(NTAPI* my_RtlInitUnicodeString) (
		PUNICODE_STRING DestinationString,
		PCWSTR SourceString
		);

	// TODO: fix
	my_RtlInitUnicodeString RtlInitUnicodeString = (my_RtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	HKEY driver_service;
	std::wstring servicesPath = L"SYSTEM\\ControlSet001\\Services\\" + ce_driver::GetDriverNameW();
	LSTATUS status = RegOpenKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &driver_service);
	if (status != ERROR_SUCCESS) {
		if (status == ERROR_FILE_NOT_FOUND) {
			return true;
		}
		return false;
	}
	RegCloseKey(driver_service);
	typedef NTSTATUS(*NtUnloadDriver)(PUNICODE_STRING DriverServiceName);

	NtUnloadDriver myNtUnloadDriver = (NtUnloadDriver)GetProcAddress(ntdll, "NtUnloadDriver");
	NTSTATUS st = (NTSTATUS)myNtUnloadDriver(&serviceStr);

	if (st != 0x0) {

#ifdef _DEBUG
		Log("NtUnloadDriver Status 0x%x", st);
#endif // _DEBUG

		Log("Driver Unload Failed!!");
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
