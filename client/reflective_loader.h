#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>


typedef HMODULE (WINAPI *fn_LoadLibraryA_t)  (LPCSTR);
typedef FARPROC (WINAPI *fn_GetProcAddress_t) (HMODULE, LPCSTR);
typedef LPVOID  (WINAPI *fn_VirtualAlloc_t)   (LPVOID, SIZE_T, DWORD, DWORD);
typedef void    (WINAPI *fn_RtlFlushCache_t)  (HANDLE, LPVOID, SIZE_T);

/* Parametri passati al ReflectiveLoader nel processo sacrificale.
 * Tutti i puntatori sono nel address space del processo FIGLIO. */
typedef struct {
    uint8_t              *pe_base;    
    fn_LoadLibraryA_t     fnLoadLib;  /* kernel32!LoadLibraryA  */
    fn_GetProcAddress_t   fnGetProc;  /* kernel32!GetProcAddress */
    fn_VirtualAlloc_t     fnVAlloc;   /* kernel32!VirtualAlloc  */
    fn_RtlFlushCache_t    fnFlush;    /* ntdll!RtlFlushInstructionCache */
} LoaderParam;

DWORD WINAPI ReflectiveLoader(LPVOID param);
int          pe_is_dotnet(const uint8_t *pe_bytes);