#pragma once
#include <Windows.h>
#include <winternl.h>

#include <stdio.h>
#include <string>
#include "ce_driver.hpp"

namespace service {
	typedef NTSTATUS(*pRtlAdjustPrivilege)(_In_ ULONG Privilege, _In_ BOOLEAN Enable, _In_ BOOLEAN Client, _Out_ PBOOLEAN WasEnabled);
	typedef NTSTATUS(*pNtLoadDriver)(_In_ PUNICODE_STRING DriverServiceName);
	typedef VOID(*pRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
	typedef NTSTATUS(*pNtUnloadDriver)(PUNICODE_STRING DriverServiceName);

	bool RegisterAndStart(const std::wstring& driver_path);
	bool StopAndRemove(const std::wstring& driver_name);
}