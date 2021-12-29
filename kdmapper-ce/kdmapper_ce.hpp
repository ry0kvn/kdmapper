#pragma once
#include "utils.hpp"
#pragma once
#include <Windows.h>
#include <iostream>
#include <string.h>
#include "ce_driver.hpp"
#include "utils.hpp"
#include "Kernelmoduleunloader_resource.hpp"
#include "Kernelmoduleunloader_sig_resource.hpp"

namespace kdmapper_ce {
	HANDLE GetDbk64DeviceHandle();
}