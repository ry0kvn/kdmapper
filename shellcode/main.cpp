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

int main()
{

    // Init APIs
    // resolve kernel32 image base
    // Stack based strings for libraries and functions the shellcode needs
    wchar_t kernel32_dll_name[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };
    char load_lib_name[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
    char get_proc_name[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s', 0 };
    char create_file_name[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'W', 0 };
    char sleep_name[] = { 'S', 'l', 'e', 'e', 'p', 0 };

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

    // CreateFile to Open the "\\\\.\\CDRIVER73" handle.
    //thandle.file_handle =  _CreateFileW(L"\\\\.\\CEDRIVER60", FILE_ANY_ACCESS, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    struct handle_marks {
        DWORD marks;
        HANDLE handle;
    };
    handle_marks mhandle = {
        0x12345678,
        _CreateFileW(L"\\\\.\\EvilCEDRIVER73", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)
    };

    // TODO “K“–‚ÈŽžŠÔ‘Ò‹@D
    VOID(WINAPI * _Sleep)(
        _In_          DWORD                       dwMilliseconds
        ) =
        (VOID(WINAPI*)(
            _In_          DWORD                       dwMilliseconds
            )) _GetProcAddress((HMODULE)base, sleep_name);

    //   _Sleep(1000*10); // 10s
    printf("0x%x, 0x%p", mhandle.marks, mhandle.handle);
    return 0;
}