#include "UserPISCreator.hpp"

extern "C"
void 
__declspec(safebuffers)
__declspec(noinline)
__stdcall PicStart(PVOID StartContext)
{
    
    UserPisParameters* pisParameters = (UserPisParameters*)StartContext;

    // Init strings

    wchar_t kernel32_dll_name[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };
    char load_lib_name[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
    char get_proc_name[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s', 0 };
    char create_file_name[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'W', 0 };
    char output_debug_strings[] = { 'O', 'u', 't', 'p', 'u', 't', 'D', 'e', 'b', 'u', 'g', 'S', 't', 'r', 'i', 'n', 'g', 'A', 0 };
    char sleep_name[] = { 'S', 'l', 'e', 'e', 'p', 0 };
    char greeting[] = { 'H', 'e', 'l', 'l', 'o', ' ', 'f', 'r', 'o', 'm', ' ', 'K', 'e', 'r', 'n', 'e', 'l', 'M', 'o', 'd', 'u', 'l', 'e', 'U', 'n', 'l', 'o', 'a', 'd', 'e', 'r', '.', 'e', 'x', 'e', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', 0 };
    char end[] = { 'W', 'a', 'i', 't', 'i', 'n', 'g', ' ', 't', 'o', ' ', 'b', 'e', ' ', 'k', 'i', 'l', 'l', 'e', 'd', '.', 0 };
    char error[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'W', ' ', 'F', 'a', 'i', 'l', 'e', 'd', 0 };

    // resolve kernel32 image base

    HMODULE base = (HMODULE)get_module_by_name((const LPWSTR)kernel32_dll_name);
    if (!base)
        return;

    // resolve getprocaddress() address

    LPVOID get_proc = get_func_by_name(base, (LPSTR)get_proc_name);
    if (!get_proc)
        return;

    // Get function addresses

    pGetProcAddress  GetProcAddress = (pGetProcAddress)get_proc;
    pOutputDebugStringA OutputDebugStringA = (pOutputDebugStringA)GetProcAddress(base, output_debug_strings);
    pCreateFileW CreateFileW = (pCreateFileW)GetProcAddress(base, create_file_name);
    pSleep Sleep = (pSleep)GetProcAddress(base, sleep_name);

    OutputDebugStringA(greeting);
    
    pisParameters->Handle = (DWORD)CreateFileW(
        pisParameters->SymName,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (pisParameters->Handle == NULL)
        OutputDebugStringA(error);
    else
        OutputDebugStringA(end);

    //  Wait appropriately until the parent process reads the handle.

    Sleep(1000 * 10); // 10s
    
}

int main()
{
    wchar_t symbol_name[] = { '\\', '\\', '.', '\\', 'E', 'v', 'i', 'l', 'C', 'E', 'D', 'R', 'I', 'V', 'E', 'R', '7', '3', 0 };
    UserPisParameters pisParameters;
    
    pisParameters.Handle = 0x12345678;
    memcpy(pisParameters.SymName, symbol_name, sizeof symbol_name);
    
    PicStart(&pisParameters);
    return 0;
}