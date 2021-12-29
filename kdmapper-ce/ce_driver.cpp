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

HANDLE ce_driver::Load() {
	srand((unsigned)time(NULL) * GetCurrentThreadId());
	
	//if (ce_driver::IsRunning()) {
	//	Log(L"[-] \\Device\\Nal is already in use." << std::endl);
	//	return INVALID_HANDLE_VALUE;
	//}

	//Randomize name for log in registry keys, usn jornal and other shits
	memset(ce_driver::driver_name, 0, sizeof(ce_driver::driver_name));
	static const char alphanum[] =
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	int len = rand() % 20 + 10;
	for (int i = 0; i < len; ++i)
		ce_driver::driver_name[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	
	Log("Loading vulnerable driver: %s", ce_driver::driver_name);

	std::wstring driver_path = GetDriverPath();
	if (driver_path.empty()) {
		Log("Can't find TEMP folder");
		return INVALID_HANDLE_VALUE;
	}

	_wremove(driver_path.c_str());

	//if (!utils::CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(helloworld_driver_resource::driver), sizeof(helloworld_driver_resource::driver))) {
	//	Log("Failed to create vulnerable driver file");
	//	return INVALID_HANDLE_VALUE;
	//}
	//if (!utils::CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(test_dbk64_driver_resource::driver), sizeof(test_dbk64_driver_resource::driver))) {
	//	Log("Failed to create vulnerable driver file");
	//	return INVALID_HANDLE_VALUE;
	//}
	if (!utils::CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(dbk64_driver_resource::driver), sizeof(dbk64_driver_resource::driver))) {
		Log("Failed to create vulnerable driver file");
		return INVALID_HANDLE_VALUE;
	}

	if (!service::RegisterAndStart(driver_path)) {
		Log("Failed to register and start service for the vulnerable driver");
		_wremove(driver_path.c_str());
		return INVALID_HANDLE_VALUE;
	}
	Log("Successfully loaded the vulnerable driver");

	if (!service::StopAndRemove(ce_driver::GetDriverNameW())) {
		Log("Failed to stop and remove service for the vulnerable driver");
		_wremove(driver_path.c_str());
		return INVALID_HANDLE_VALUE;
	}

	Log("Successfully unloaded the vulnerable driver");
	HANDLE result = INVALID_HANDLE_VALUE;

//	HANDLE result = CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	//HANDLE result = CreateFile(L"\\\\.\\CEDRIVER73", GENERIC_READ | GENERIC_WRITE,
	//	FILE_SHARE_READ |
	//	FILE_SHARE_WRITE,
	//	NULL,
	//	OPEN_EXISTING,
	//	0,
	//	NULL);

	return result;
}