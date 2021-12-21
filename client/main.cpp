#include "main.hpp"

int wmain(int argc, wchar_t* argv[]) {

	const wchar_t* LoaderServiceName = LOADER_SERVICE_NAME;
	const wchar_t* LoaderDriverName = LOADER_DRIVER_NAME;
	const wchar_t* DriverName = argv[1];
	wchar_t DriverFullPath[MAX_PATH] = { 0 };
	wchar_t LoaderDriverFullPath[MAX_PATH] = { 0 };
	HANDLE hDriver = NULL;


	// TODO:
	//ScanParam(argc, argv);

	// reflectiveロードされるドライバのフルパスを取得

	if (!_wfullpath(DriverFullPath, DriverName, MAX_PATH))
		ErrorAndReturnZero("_wfullpath failed");


	// 引数で与えられたファイルをメモリに読み込む

	hDriver = utils::ReadFileToMemory(DriverFullPath);
	if (hDriver == INVALID_HANDLE_VALUE)
		ErrorAndReturnZero("ReadFileToMemory failed");


	// サービスを作成，開始

	if (!_wfullpath(LoaderDriverFullPath, LoaderDriverName, MAX_PATH))
		ErrorAndReturnZero("_wfullpath failed");

	utils::RegisterAndStartLoaderService(LoaderServiceName, LoaderDriverFullPath);


	//ドライバのreflectiveなロード

	if (!ReflectiveLoad(hDriver)) {
		utils::UninstallDriver(LoaderServiceName);
		ErrorAndReturnZero("ReflectiveLoad failed");
	}

	utils::UninstallDriver(LoaderServiceName);
	Log("Kernel mode driver reflective loading complete!");

	return 0;
}

bool ReflectiveLoad(const HANDLE hDriver) {

	ntoskrnlAddr = utils::GetKernelModuleAddress("ntoskrnl.exe");

	// Open the device

	HANDLE hDevice = CreateFile(RL_USER_SYM_NAME,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr,
		OPEN_EXISTING,
		0,
		nullptr);

	if (hDevice == INVALID_HANDLE_VALUE)
		ErrorAndReturnZero("Failed to open device");

	// Alloc kernel memory space

	const PIMAGE_NT_HEADERS64 ntHeaders = portable_executable::GetNtHeaders(hDriver);

	if (!ntHeaders)
		ErrorAndReturnZero("[-] Invalid format of PE image")
		
	if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		ErrorAndReturnZero("[-] Image is not 64 bit")

	uint32_t ImageSize = ntHeaders->OptionalHeader.SizeOfImage;

	void* LocalImageBase = VirtualAlloc(nullptr, ImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!LocalImageBase)
		return 0;


	uint64_t KernelImageBase = AllocatePool(hDevice, ImageSize);


	do {
		if (!KernelImageBase)
			ErrorAndBreak("Failed to allocate remote image in kernel");
			
		Log("Image base has been allocated at 0x%p", KernelImageBase);

		// Copy image headers

		memcpy(LocalImageBase, (BYTE*)hDriver, ntHeaders->OptionalHeader.SizeOfHeaders);

		// Copy image sections

		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
		for (auto i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
		{
			if ((section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
				continue;
			auto sectionDestination = (LPVOID)((DWORD_PTR)LocalImageBase + (DWORD_PTR)section->VirtualAddress);
			auto sectionBytes = (LPVOID)((DWORD_PTR)hDriver + (DWORD_PTR)section->PointerToRawData);
			memcpy(sectionDestination, sectionBytes, section->SizeOfRawData);
			section++;
		}

		// Resolve relocs and imports
		DWORD_PTR deltaImageBase = (DWORD_PTR)KernelImageBase - (DWORD_PTR)ntHeaders->OptionalHeader.ImageBase;
		portable_executable::RelocateImageByDelta(portable_executable::GetRelocs(LocalImageBase), deltaImageBase);

		if (!ResolveImports(hDevice, portable_executable::GetImports(LocalImageBase)))
			ErrorAndBreak("Failed to resolve imports");

		// Write fixed image to kernel

		if (!WriteMemory(hDevice, KernelImageBase, (PVOID)((uintptr_t)LocalImageBase), ImageSize))
			ErrorAndBreak("Failed to write local image to remote image");

		// Call driver entry point

		const uint64_t address_of_entry_point = KernelImageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;

		Log("Calling DriverEntry 0x%p", address_of_entry_point);
		if (!CallDriverEntry(hDevice, address_of_entry_point))
			ErrorAndBreak("Failed to call driver entry")

	} while (false);


	VirtualFree(LocalImageBase, 0, MEM_RELEASE);

	FreePool(hDevice, KernelImageBase);

	return TRUE;
}

uint64_t AllocatePool(HANDLE hDevice, SIZE_T Size) {

	auto ioCtlCode = IOCTL_ALLOCATEMEM_NONPAGED;
	DWORD returned;
	uint64_t alloc_size = 0;

	struct input
	{
		SIZE_T Size;
	}inp ={ Size };


	if (DeviceIoControl(hDevice, ioCtlCode, &inp,	sizeof input,	&alloc_size,	sizeof(uint64_t),	&returned, nullptr))
		return alloc_size;
	else
		return NULL;

}

bool FreePool(HANDLE hDevice, UINT64 address) {

	auto ioCtlCode = IOCTL_FREE_NONPAGED;
	DWORD returned;

	if (DeviceIoControl(hDevice, ioCtlCode, &address, sizeof UINT64, nullptr, 0, &returned, nullptr))
		return TRUE;
	else
		return FALSE;

}

uint64_t MmGetSystemRoutineAddress(HANDLE hDevice, std::string function_name) {

	auto ioCtlCode = IOCTL_GETPROCADDRESS;
	DWORD returned;
	uint64_t function_address = NULL;
	std::wstring func_name(function_name.begin(), function_name.end());

	struct input
	{
		UINT64 s;
	} inp = { (UINT64)func_name.c_str() };

	if (DeviceIoControl(hDevice, ioCtlCode, &inp, sizeof input, &function_address, sizeof uint64_t, &returned, nullptr))
		return function_address;
	else
		return NULL;

}

bool ReadMemory(HANDLE hDevice, uint64_t address, void* buffer, uint64_t size) {

	return false;
}

bool WriteMemory(HANDLE hDevice, uint64_t address, void* buffer, uint64_t size) {

	auto ioCtlCode = IOCTL_WRITEMEMORY;
	DWORD returned;

	struct input
	{
		UINT64 destination;
		SIZE_T source;
		UINT64 size;
	} inp = { address, (UINT64)buffer, size };

	if (DeviceIoControl(hDevice, ioCtlCode, &inp, sizeof input, nullptr, 0, &returned, nullptr))
		return TRUE;
	else
		return FALSE;

}

bool CallDriverEntry(HANDLE hDevice, UINT64 EntryPoint) {

	auto ioCtlCode = IOCTL_EXECUTE_CODE;
	DWORD returned;

	struct input
	{
		UINT64	functionaddress;
		UINT64	parameters;
	}inp = { EntryPoint, NULL };

	if (DeviceIoControl(hDevice, ioCtlCode, &inp, sizeof input, nullptr, 0, &returned, nullptr))
		return TRUE;
	else
		return FALSE;

}

uint64_t GetKernelModuleExport(HANDLE hDevice, uint64_t kernel_module_base, const std::string& function_name) {
	if (!kernel_module_base)
		return 0;

	IMAGE_DOS_HEADER dos_header = { 0 };
	IMAGE_NT_HEADERS64 ntHeaders = { 0 };

	if (!ReadMemory(hDevice, kernel_module_base, &dos_header, sizeof(dos_header)) || dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
		!ReadMemory(hDevice, kernel_module_base + dos_header.e_lfanew, &ntHeaders, sizeof(ntHeaders)) || ntHeaders.Signature != IMAGE_NT_SIGNATURE)
		return 0;

	const auto export_base = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	const auto export_base_size = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	if (!export_base || !export_base_size)
		return 0;

	const auto export_data = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(VirtualAlloc(nullptr, export_base_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (!ReadMemory(hDevice, kernel_module_base + export_base, export_data, export_base_size))
	{
		VirtualFree(export_data, 0, MEM_RELEASE);
		return 0;
	}

	const auto delta = reinterpret_cast<uint64_t>(export_data) - export_base;

	const auto name_table = reinterpret_cast<uint32_t*>(export_data->AddressOfNames + delta);
	const auto ordinal_table = reinterpret_cast<uint16_t*>(export_data->AddressOfNameOrdinals + delta);
	const auto function_table = reinterpret_cast<uint32_t*>(export_data->AddressOfFunctions + delta);

	for (auto i = 0u; i < export_data->NumberOfNames; ++i) {
		const std::string current_function_name = std::string(reinterpret_cast<char*>(name_table[i] + delta));

		if (!_stricmp(current_function_name.c_str(), function_name.c_str())) {
			const auto function_ordinal = ordinal_table[i];
			if (function_table[function_ordinal] <= 0x1000) {
				// Wrong function address?
				return 0;
			}
			const auto function_address = kernel_module_base + function_table[function_ordinal];

			if (function_address >= kernel_module_base + export_base && function_address <= kernel_module_base + export_base + export_base_size) {
				VirtualFree(export_data, 0, MEM_RELEASE);
				return 0; // No forwarded exports on 64bit?
			}

			VirtualFree(export_data, 0, MEM_RELEASE);
			return function_address;
		}
	}

	VirtualFree(export_data, 0, MEM_RELEASE);
	return 0;
}

bool ResolveImports(HANDLE hDevice, portable_executable::vec_imports imports) {
	for (const auto& current_import : imports) {
		ULONG64 Module = utils::GetKernelModuleAddress(current_import.module_name);
		if (!Module) {
#if !defined(DISABLE_OUTPUT)
			Log("Dependency %s wasn't found", current_import.module_name);
#endif
			return false;
		}

		for (auto& current_function_data : current_import.function_datas) {
			//uint64_t function_address = GetKernelModuleExport(hDevice, Module, current_function_data.name);
			//TODO:
			// 現状ntoskrnlのみ対応
			uint64_t function_address = MmGetSystemRoutineAddress(hDevice, current_function_data.name);

			if (!function_address) {
				//Lets try with ntoskrnl
				if (Module != ntoskrnlAddr) {
					function_address = GetKernelModuleExport(hDevice, ntoskrnlAddr, current_function_data.name);
					if (!function_address) {
#if !defined(DISABLE_OUTPUT)
						Log("Failed to resolve import %s (%s)", current_function_data.name, current_import.module_name);
#endif
						return false;
					}
				}
			}

			*current_function_data.address = function_address;
		}
	}

	return true;
}