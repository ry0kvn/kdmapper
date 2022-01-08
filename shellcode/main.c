#include <Windows.h>
#include <stdio.h>
#ifndef __NTDLL_H__

#ifndef TO_LOWERCASE
#define TO_LOWERCASE(out, c1) (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a': c1)
#endif


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

inline LPVOID get_module_by_name(WCHAR* module_name)
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

// It's worth noting that strings can be defined nside the .text section:
#pragma code_seg(".text")

//__declspec(allocate(".text"))
//DWORD premark = 0x12345678;
//
//__declspec(allocate(".text"))
//HANDLE handle = NULL;
//
//__declspec(allocate(".text"))
//DWORD postmark = 0x12345678;


int main()
{
    struct handle_marks {
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
    char virtial_protect_name[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0};
    char sleep_name[] = { 'S', 'l', 'e', 'e', 'p', 0 };
    char output_debug_strings[] = {'O', 'u', 't', 'p', 'u', 't', 'D', 'e', 'b', 'u', 'g', 'S', 't', 'r', 'i', 'n', 'g', 'A', 0};
    char virtual_alloc_name[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0 };
    char write_process_memory_name[] = { 'W', 'r', 'i', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y', 0 };
    char get_current_process_name[] = {'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 0};
    wchar_t symbol_name[] = { '\\', '\\', '.', '\\', 'E', 'v', 'i', 'l', 'C', 'E', 'D', 'R', 'I', 'V', 'E', 'R', '7', '3', 0};


    // resolve kernel32 image base
    LPVOID base = get_module_by_name((const LPWSTR)kernel32_dll_name);
    if (!base) {
        return 1;
    }

    // resolve getprocaddress() address
    LPVOID get_proc = get_func_by_name((HMODULE)base, (LPSTR)get_proc_name);
    if (!get_proc) {
        return 3;
    }

    // getprocaddress function definitions
    FARPROC(WINAPI * _GetProcAddress)(HMODULE hModule, LPCSTR lpProcName)
        = (FARPROC(WINAPI*)(HMODULE, LPCSTR)) get_proc;


    BOOL(WINAPI * _OutputDebugStringA)(
        LPCSTR lpOutputString
        ) =
        (BOOL(WINAPI*)(
            LPCSTR lpOutputString
            )) _GetProcAddress((HMODULE)base, output_debug_strings);

    _OutputDebugStringA("[+]shellcode Init");


    /*BOOL(WINAPI * _VirtualProtect)(
        _In_  LPVOID lpAddress,
        _In_  SIZE_T dwSize,
        _In_  DWORD  flNewProtect,
         PDWORD lpflOldProtect
        ) =
        (BOOL(WINAPI*)(
            _In_  LPVOID lpAddress,
            _In_  SIZE_T dwSize,
            _In_  DWORD  flNewProtect,
            PDWORD lpflOldProtect
            )) _GetProcAddress((HMODULE)base, virtial_protect_name);*/


    HANDLE(WINAPI * _CreateFileW)(
        _In_          LPCWSTR               lpFileName,
        _In_          DWORD                 dwDesiredAccess,
        _In_           DWORD                 dwShareMode,
        _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        _In_         DWORD                 dwCreationDisposition,
        _In_         DWORD                 dwFlagsAndAttributes,
        _In_opt_ HANDLE                hTemplateFile
        ) =
        (HANDLE(WINAPI*)(
            _In_          LPCWSTR               lpFileName,
            _In_          DWORD                 dwDesiredAccess,
            _In_           DWORD                 dwShareMode,
            _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
            _In_         DWORD                 dwCreationDisposition,
            _In_         DWORD                 dwFlagsAndAttributes,
            _In_opt_ HANDLE                hTemplateFile
            )) _GetProcAddress((HMODULE)base, create_file_name);

    //BOOL bRet = FALSE;
    //HANDLE hToken = NULL;
    //LUID luid = { 0 };

    //if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    //{
    //    if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
    //    {
    //        TOKEN_PRIVILEGES tokenPriv = { 0 };
    //        tokenPriv.PrivilegeCount = 1;
    //        tokenPriv.Privileges[0].Luid = luid;
    //        tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    //        bRet = AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    //    }
    //}  
    //if (!bRet) {
    //    printf("RtlAdjustPrivilege failed\n");
    //    return -1;
    //}


    //DWORD oldProtect = 0;
    //_VirtualProtect(&handle, sizeof(HANDLE), PAGE_EXECUTE_READWRITE, &oldProtect);
    //_OutputDebugStringA("[+]shellcode VirtualProtect");

    handle_marks.handle = _CreateFileW(
        symbol_name,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, 
        NULL, 
        OPEN_EXISTING, 
        FILE_ATTRIBUTE_NORMAL, 
        NULL
    );

    //HANDLE hDevice = CreateFile(L"\\\\.\\EvilCEDRIVER73", GENERIC_READ| GENERIC_WRITE, FILE_SHARE_WRITE,
    //    NULL, OPEN_EXISTING, 0, NULL);

    _OutputDebugStringA("[+]shellcode _CreateFileA");

    //_VirtualProtect(&handle, sizeof(HANDLE), oldProtect, 0);
    
    LPVOID(WINAPI* _VirtualAlloc)(
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flAllocationType,
        DWORD  flProtect
        ) =
        (LPVOID(WINAPI*)(
            LPVOID lpAddress,
            SIZE_T dwSize,
            DWORD  flAllocationType,
            DWORD  flProtect
            )) _GetProcAddress((HMODULE)base, virtual_alloc_name);


    BOOL(WINAPI * _WriteProcessMemory)(
        HANDLE  hProcess,
        LPVOID  lpBaseAddress,
        LPCVOID lpBuffer,
        SIZE_T  nSize,
        SIZE_T * lpNumberOfBytesWritten
        ) =
        (BOOL(WINAPI*)(
            HANDLE  hProcess,
            LPVOID  lpBaseAddress,
            LPCVOID lpBuffer,
            SIZE_T  nSize,
            SIZE_T * lpNumberOfBytesWritten
            )) _GetProcAddress((HMODULE)base, write_process_memory_name);

    HANDLE(WINAPI * _GetCurrentProcess)(
        ) =
        (HANDLE(WINAPI*)(
            )) _GetProcAddress((HMODULE)base, get_current_process_name);

    struct handle_marks *lpBuffer = _VirtualAlloc(NULL, sizeof(handle_marks), (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
    
    _OutputDebugStringA("[+]shellcode _VirtualAlloc");

    _WriteProcessMemory(_GetCurrentProcess(), lpBuffer, &handle_marks, sizeof(handle_marks), NULL);

    _OutputDebugStringA("[+]shellcode _WriteProcessMemory");
    
    //printf("Allocated at 0x%x(%d bytes)\n", lpBuffer, sizeof(handle_marks));
    //printf("original: 0x%x, 0x%x, 0x%x\n", handle_marks.marks, handle_marks.handle, handle_marks.marks2);
    //printf("copied: 0x%x, 0x%x, 0x%x\n", lpBuffer->marks, lpBuffer->handle, lpBuffer->marks2);

    
    // TODO ìKìñÇ»éûä‘ë“ã@ÅD
    VOID(WINAPI * _Sleep)(
        _In_          DWORD                       dwMilliseconds
        ) =
        (VOID(WINAPI*)(
            _In_          DWORD                       dwMilliseconds
            )) _GetProcAddress((HMODULE)base, sleep_name);

    //printf("EvilCEDRIVER73 handle: %d\n", handle);
     _Sleep(1000*10); // 10s
     _OutputDebugStringA("[+]shellcode _Sleep");

     return 0;
}