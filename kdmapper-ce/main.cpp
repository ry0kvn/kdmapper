#include "main.h"

int wmain(const int argc, wchar_t** argv) {

	utils::KdmapperInit();

#if _DEBUG
	Log("Debug Mode Enable");
#endif
	
	wchar_t DriverFullPath[MAX_PATH] = { 0 };
	const wchar_t* DriverName = argv[1];
	HANDLE hDriver = NULL;
	
	// コマンドライン引数に与えられたファイルをメモリにロード
	
	if (argc < 2) {
		Error("Usage: kdmapper-ce.exe <driver_path>");
		return -1;
	}

	// reflectiveロードされるドライバのフルパスを取得

	if (!_wfullpath(DriverFullPath, DriverName, MAX_PATH)) {
		Error("_wfullpath failed");
		return -1;
	}

	hDriver = utils::ReadFileToMemory(DriverFullPath);
	if (hDriver == INVALID_HANDLE_VALUE) {
		Error("ReadFileToMemory failed");
		return -1;
	}

	HANDLE dbk64_device_handle = ce_driver::Load();
	if (dbk64_device_handle == INVALID_HANDLE_VALUE) {
		Error("ce_driver::Load() failed");
		return -1;
	}

		
	// TODO: dbk64ファイルをディスクにドロップ
	// TODO: サービスの作成，開始
	// TODO: ドロップしたdbk64ファイルを削除
	// TODO: kernelmoduleunloaderにシェルコードをインジェクトし，dbk64サービスのハンドルを取得
	// TODO: DeviceIoControlを使いドライバをロード
	// TODO: サービスの停止，削除
	
	getchar();
	return 0;
}
