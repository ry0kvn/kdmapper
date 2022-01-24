#include "UserPISCreator.hpp"



extern "C"
void 
__declspec(safebuffers)
__declspec(noinline)
__stdcall PicStart()
{
    //OutputDebugString(StartContext.symbol_name);

    HANDLE_MARKS handle_marks = { 0x12345678, NULL, 0x12345678 };

    // Init strings
    wchar_t kernel32_dll_name[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };
    char load_lib_name[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
    char get_proc_name[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s', 0 };
    char create_file_name[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'W', 0 };
    char virtial_protect_name[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0 };
    char sleep_name[] = { 'S', 'l', 'e', 'e', 'p', 0 };
    char output_debug_strings[] = { 'O', 'u', 't', 'p', 'u', 't', 'D', 'e', 'b', 'u', 'g', 'S', 't', 'r', 'i', 'n', 'g', 'A', 0 };
    char virtual_alloc_name[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0 };
    char write_process_memory_name[] = { 'W', 'r', 'i', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y', 0 };
    char get_current_process_name[] = { 'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 0 };
    wchar_t symbol_name[] = { '\\', '\\', '.', '\\', 'E', 'v', 'i', 'l', 'C', 'E', 'D', 'R', 'I', 'V', 'E', 'R', '7', '3', 0 };
    char greeting[] = { 'H', 'e', 'l', 'l', 'o', ' ', 'f', 'r', 'o', 'm', ' ', 'K', 'e', 'r', 'n', 'e', 'l', 'M', 'o', 'd', 'u', 'l', 'e', 'U', 'n', 'l', 'o', 'a', 'd', 'e', 'r', '.', 'e', 'x', 'e', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', 0 };
    char end[] = { 'W', 'a', 'i', 't', 'i', 'n', 'g', ' ', 't', 'o', ' ', 'b', 'e', ' ', 'k', 'i', 'l', 'l', 'e', 'd', '.', 0 };

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
    pVirtualAlloc VirtualAlloc = (pVirtualAlloc)GetProcAddress(base, virtual_alloc_name);
    pWriteProcessMemory WriteProcessMemory = (pWriteProcessMemory)GetProcAddress(base, write_process_memory_name);
    pGetCurrentProcess GetCurrentProcess = (pGetCurrentProcess)GetProcAddress(base, get_current_process_name);
    pSleep Sleep = (pSleep)GetProcAddress(base, sleep_name);

    OutputDebugStringA(greeting);
    
    //StartContext.Handle = CreateFileW(
    //    //symbol_name,
    //    (LPCWSTR)StartContext.symbol_name,
    //    GENERIC_READ | GENERIC_WRITE,
    //    FILE_SHARE_READ | FILE_SHARE_WRITE,
    //    NULL,
    //    OPEN_EXISTING,
    //    FILE_ATTRIBUTE_NORMAL,
    //    NULL
    //);

    handle_marks.handle = CreateFileW(
        symbol_name,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    
    HANDLE_MARKS* lpBuffer = (HANDLE_MARKS*)VirtualAlloc(NULL, sizeof(HANDLE_MARKS), (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);

    WriteProcessMemory(GetCurrentProcess(), lpBuffer, &handle_marks, sizeof(HANDLE_MARKS), NULL);

    OutputDebugStringA(end);

    // 親プロセスがハンドルをreadするまで適当に待機
    Sleep(1000 * 10); // 10s
    
}

int main()
{
    PicStart();
    return 0;
}