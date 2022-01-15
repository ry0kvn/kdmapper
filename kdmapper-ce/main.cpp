#include "main.h"


int wmain(const int argc, wchar_t** argv) {

	utils::KdmapperInit();

#if _DEBUG
	Log("Debug Mode Enable");
#endif

	wchar_t DriverFullPath[MAX_PATH] = { 0 };
	wchar_t LoaderDriverFullPath[MAX_PATH] = { 0 };
	const wchar_t* LoaderDriverName = argv[1];
	const wchar_t* DriverName = argv[2];
	HANDLE hDriver = NULL;

	// コマンドライン引数に与えられたファイルをメモリにロード

	if (argc < 3) {
		Error("Usage: kdmapper-ce.exe <driver_path>");
		return -1;
	}

	// reflectiveロードされるドライバのフルパスを取得
	// TODO: std::filesystem::pathを使って書き直し

	if (!_wfullpath(DriverFullPath, DriverName, MAX_PATH)) {
		Error("_wfullpath failed");
		return -1;
	}

	hDriver = utils::ReadFileToMemory(DriverFullPath);
	if (hDriver == INVALID_HANDLE_VALUE) {
		Error("ReadFileToMemory failed");
		return -1;
	}


	if (!_wfullpath(LoaderDriverFullPath, LoaderDriverName, MAX_PATH)) {
		Error("_wfullpath failed");
		return -1;
	}

	std::wstring laoder_driver_path = LoaderDriverFullPath;
	if (laoder_driver_path.empty()) {
		Log("Can't find TEMP folder");
		return -1;
	}
	std::wstring loader_driver_name = LoaderDriverName;
	if (!service::RegisterAndStart(laoder_driver_path, loader_driver_name.substr(0, loader_driver_name.find('.')))) {
		Error("RegisterAndStart failed");
		return -1;
	}

	do {

		// Open the device
#define RL_DEVICE_NAME L"\\Device\\KernelPISCreator"
#define RL_SYM_NAME L"\\??\\KernelPISCreator"
#define RL_USER_SYM_NAME L"\\\\.\\KernelPISCreator"

		HANDLE device_handle = CreateFile(RL_USER_SYM_NAME,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			nullptr,
			OPEN_EXISTING,
			0,
			nullptr);


		NTSTATUS exitCode = 0;
		if (!kdmapper_ce::MapDriver(device_handle, hDriver, &exitCode)) {
			Error("Failed to map %ls", DriverName);
			break;
		}

#ifdef _DEBUG
		Log("exitCode: %d", exitCode);
#endif // _DEBUG

	} while (FALSE);


	// サービスの停止，削除
	if (!service::StopAndRemove(loader_driver_name.substr(0, loader_driver_name.find('.')))) {
		Error("Failed to stop and remove service for the vulnerable driver");
		_wremove(LoaderDriverName);
		return -1;
	}

	return 0;
}