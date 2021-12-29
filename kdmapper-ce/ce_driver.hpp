#pragma once
#include <Windows.h>
#include <stdio.h>
#include <string>
#include <time.h>

#include "utils.hpp"
#include "service.hpp"
#include "dbk64_driver_resource.hpp"

#if _DEBUG
#include "helloworld_driver_resource.hpp"
#include "test_dbk64_driver_resource.hpp"
#endif


namespace ce_driver {
	extern char driver_name[100] ; // dbk64.sys

	std::wstring GetDriverNameW();
	std::wstring GetDriverPath();
	HANDLE Load();
}