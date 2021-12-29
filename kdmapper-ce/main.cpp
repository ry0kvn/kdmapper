#include "main.h"


int wmain(const int argc, wchar_t** argv) {

	utils::KdmapperInit();

#if _DEBUG
	Log("Debug Mode Enable");
#endif

	wchar_t DriverFullPath[MAX_PATH] = { 0 };
	const wchar_t* DriverName = argv[1];
	const wchar_t DeviceName[] = L"\\\\.\\CEDRIVER73";
	HANDLE hDriver = NULL;

	// コマンドライン引数に与えられたファイルをメモリにロード

	if (argc < 2) {
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

	// dbk64ファイルをディスクにドロップしサービスを作成，開始

	if (!ce_driver::Load()) {
		Error("ce_driver::Load() failed");
		return -1;
	}

	// TODO: kernelmoduleunloaderにシェルコードをインジェクトし，dbk64サービスのハンドルを取得

	HANDLE dbk64_device_handle = kdmapper_ce::GetDbk64DeviceHandle();
	if (dbk64_device_handle == INVALID_HANDLE_VALUE) {
		service::StopAndRemove(ce_driver::GetDriverNameW());
		Error("kdmapper_ce::GetDbk64DeviceHandle failed");
		return -1;
	}
		
	// TODO: DeviceIoControlを使いドライバをロード

	// サービスの停止，削除
	if (!service::StopAndRemove(ce_driver::GetDriverNameW())) {
		Error("Failed to stop and remove service for the vulnerable driver");
		_wremove(ce_driver::GetDriverPath().c_str());
		return -1;
	}

	Log("Successfully unloaded the vulnerable driver");

	//getchar();
	return 0;
}