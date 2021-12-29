#pragma once
#include <Windows.h>
#include <winternl.h>

#include <stdio.h>
#include <string>
#include "ce_driver.hpp"

namespace service {
	bool RegisterAndStart(const std::wstring& driver_path);
	bool StopAndRemove(const std::wstring& driver_name);
}