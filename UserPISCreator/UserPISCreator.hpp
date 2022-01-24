#pragma once
#include <Windows.h>
#include <stdio.h>
#include "PEB_Lookup.hpp"

// structures

typedef struct _HANDLE_MARKS {
    DWORD marks;
    HANDLE handle;
    DWORD marks2;
}HANDLE_MARKS;

// function prototypes

extern "C"
void
__declspec(safebuffers)
__declspec(noinline)
__stdcall PicStart();
#pragma alloc_text(".PIS", "PicStart")


typedef FARPROC(__stdcall* pGetProcAddress)(
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
