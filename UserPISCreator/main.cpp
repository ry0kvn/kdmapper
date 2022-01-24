#include <Windows.h>
#include <stdio.h>
//#include "peb-lookup.hpp"


#ifndef __NTDLL_H__

#ifndef TO_LOWERCASE
#define TO_LOWERCASE(out, c1) (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a': c1)
#endif

extern "C"
inline LPVOID get_module_by_name(
    WCHAR * module_name
);

extern "C"
inline LPVOID get_func_by_name(
    LPVOID module,
    char* func_name
);

#pragma alloc_text(".PIS", "get_func_by_name")
#pragma alloc_text(".PIS", "get_module_by_name")

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;

} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID      EntryInProgress;

} PEB_LDR_DATA, * PPEB_LDR_DATA;

//here we don't want to use any functions imported form extenal modules

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
    void* BaseAddress;
    void* EntryPoint;
    ULONG   SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG   Flags;
    SHORT   LoadCount;
    SHORT   TlsIndex;
    HANDLE  SectionHandle;
    ULONG   CheckSum;
    ULONG   TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;

    // [...] this is a fragment, more elements follow here

} PEB, * PPEB;

#endif //__NTDLL_H__
extern "C"
inline LPVOID get_module_by_name(WCHAR * module_name)
{
    PPEB peb = NULL;
#if defined(_WIN64)
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY list = ldr->InLoadOrderModuleList;

    PLDR_DATA_TABLE_ENTRY Flink = *((PLDR_DATA_TABLE_ENTRY*)(&list));
    PLDR_DATA_TABLE_ENTRY curr_module = Flink;

    while (curr_module != NULL && curr_module->BaseAddress != NULL) {
        if (curr_module->BaseDllName.Buffer == NULL) continue;
        WCHAR* curr_name = curr_module->BaseDllName.Buffer;

        size_t i = 0;
        for (i = 0; module_name[i] != 0 && curr_name[i] != 0; i++) {
            WCHAR c1, c2;
            TO_LOWERCASE(c1, module_name[i]);
            TO_LOWERCASE(c2, curr_name[i]);
            if (c1 != c2) break;
        }
        if (module_name[i] == 0 && curr_name[i] == 0) {
            //found
            return curr_module->BaseAddress;
        }
        // not found, try next:
        curr_module = (PLDR_DATA_TABLE_ENTRY)curr_module->InLoadOrderModuleList.Flink;
    }
    return NULL;
}

extern "C"
inline LPVOID get_func_by_name(LPVOID module, char* func_name)
{
    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
    IMAGE_DATA_DIRECTORY* exportsDir = &(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (exportsDir->VirtualAddress == (DWORD)NULL) {
        return NULL;
    }

    DWORD expAddr = exportsDir->VirtualAddress;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR)module);
    SIZE_T namesCount = exp->NumberOfNames;

    DWORD funcsListRVA = exp->AddressOfFunctions;
    DWORD funcNamesListRVA = exp->AddressOfNames;
    DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;

    //go through names:
    for (SIZE_T i = 0; i < namesCount; i++) {
        DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*)module + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*)module + i * sizeof(WORD));
        DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*)module + (*nameIndex) * sizeof(DWORD));

        LPSTR curr_name = (LPSTR)(*nameRVA + (BYTE*)module);
        size_t k = 0;
        for (k = 0; func_name[k] != 0 && curr_name[k] != 0; k++) {
            if (func_name[k] != curr_name[k]) break;
        }
        if (func_name[k] == 0 && curr_name[k] == 0) {
            //found
            return (BYTE*)module + (*funcRVA);
        }
    }
    return NULL;
}
typedef FARPROC (__stdcall* pGetProcAddress)(
    _In_ HMODULE hModule,
    _In_ LPCSTR  lpProcName
    );
typedef void(__stdcall* pOutputDebugStringA)(
    __in_opt LPCSTR lpOutputString
    );
typedef HANDLE(__stdcall* pCreateFileW)(
    _In_ LPCWSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile
    );
typedef LPVOID(__stdcall* pVirtualAlloc)(
    _In_opt_ LPVOID lpAddress,
    _In_     SIZE_T dwSize,
    _In_     DWORD flAllocationType,
    _In_     DWORD flProtect
    );
typedef BOOL(__stdcall* pWriteProcessMemory)(
    _In_ HANDLE hProcess,
    _In_ LPVOID lpBaseAddress,
    _In_reads_bytes_(nSize) LPCVOID lpBuffer,
    _In_ SIZE_T nSize,
    _Out_opt_ SIZE_T* lpNumberOfBytesWritten
    );
typedef HANDLE(__stdcall* pGetCurrentProcess)(
    VOID
    );
typedef int(__stdcall* pSleep)(
    _In_ DWORD dwMilliseconds
    );

extern "C"
void  
__declspec(safebuffers)
__declspec(noinline)
__stdcall PicStart();


#pragma alloc_text(".PIS", "PicStart")



extern "C"
void 
__declspec(safebuffers)
__declspec(noinline)
__stdcall PicStart()
{

    struct HANDLE_MARKS{
        DWORD marks;
        HANDLE handle;
        DWORD marks2;
    } handle_marks = { 0x12345678, NULL, 0x12345678 };


    // Init APIs
    // resolve kernel32 image base
    // Stack based strings for libraries and functions the shellcode needs
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
    char end[] = { '[', '+', ']', 'W', 'a', 'i', 't', 'i', 'n', 'g', ' ', 't', 'o', ' ', 'b', 'e', ' ', 'k', 'i', 'l', 'l', 'e', 'd', '.', 0 };

    // resolve kernel32 image base
    HMODULE base = (HMODULE)get_module_by_name((const LPWSTR)kernel32_dll_name);
    if (!base)
        return;

    // resolve getprocaddress() address
    LPVOID get_proc = get_func_by_name(base, (LPSTR)get_proc_name);
    if (!get_proc)
        return;

    // Get function addresses
    pGetProcAddress  _GetProcAddress = (pGetProcAddress)get_proc;
    pOutputDebugStringA _OutputDebugStringA = (pOutputDebugStringA)_GetProcAddress(base, output_debug_strings);
    pCreateFileW _CreateFileW = (pCreateFileW)_GetProcAddress(base, create_file_name);
    pVirtualAlloc _VirtualAlloc = (pVirtualAlloc)_GetProcAddress(base, virtual_alloc_name);
    pWriteProcessMemory _WriteProcessMemory = (pWriteProcessMemory)_GetProcAddress(base, write_process_memory_name);
    pGetCurrentProcess _GetCurrentProcess = (pGetCurrentProcess)_GetProcAddress(base, get_current_process_name);
    pSleep _Sleep = (pSleep)_GetProcAddress(base, sleep_name);

    _OutputDebugStringA(greeting);

    handle_marks.handle = _CreateFileW(
        symbol_name,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    
    HANDLE_MARKS* lpBuffer = (HANDLE_MARKS*)_VirtualAlloc(NULL, sizeof(HANDLE_MARKS), (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);

    _WriteProcessMemory(_GetCurrentProcess(), lpBuffer, &handle_marks, sizeof(HANDLE_MARKS), NULL);

    _OutputDebugStringA(end);

    // 親プロセスがハンドルをreadするまで適当に待機
    _Sleep(1000 * 10); // 10s
    

}

int main()
{
    PicStart();
    return 0;
}