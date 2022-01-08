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

	// dbk64.sysファイルをディスクにドロップしサービスを作成，開始
	// TODO: おそらく削除処理に漏れがある
	if (!ce_driver::Load()) {
		Error("ce_driver::Load() failed");
		return -1;
	}

	do {

		// kernelmoduleunloaderにシェルコードをインジェクトし，dbk64.sysのデバイスハンドルを取得
		Log("Injecting shellcode into KernelModuleUnloader.exe process to get device handle of Dbk64.sys...");
		HANDLE dbk64_device_handle = kdmapper_ce::GetDbk64DeviceHandle();
		if (dbk64_device_handle == INVALID_HANDLE_VALUE) {
			Error("kdmapper_ce::GetDbk64DeviceHandle failed");
			break;
		}

		// Dbk64.sysのIRP_MJ_DEVICE_CONTROLにパッチを当て，
		// ドライバをロードする代替コードでフックする
		Log("Patching IRP_MJ_DEVICE_CONTROL in Dbk64.sys driver to hook IRP...");
		if (!kdmapper_ce::PatchMajorFunction(dbk64_device_handle)) {
			Error("kdmapper_ce::PatchMajorFunction failed");
			break;
		}

		// TODO: 入力されたドライバのロード
		Log("Ready, load the input driver...");
		NTSTATUS exitCode = 0;
		if (!kdmapper_ce::MapDriver(dbk64_device_handle, hDriver, &exitCode)) {
			Error("Failed to map %s", DriverName);
			break;
		}

#ifdef _DEBUG
		Log("exitCode: %d", exitCode);
#endif // _DEBUG

	} while (FALSE);

	getchar();

	// サービスの停止，削除
	if (!service::StopAndRemove(ce_driver::GetDriverNameW())) {
		Error("Failed to stop and remove service for the vulnerable driver");
		_wremove(ce_driver::GetDriverPath().c_str());
		return -1;
	}

	return 0;
}