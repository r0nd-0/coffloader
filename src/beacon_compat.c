/*
 * beacon_compat.c — Cobalt Strike 4.X BOF Compatibility Layer
 * ------------------------------------------------------------
 * Implements the Beacon API so that BOFs compiled for Cobalt Strike
 * can run inside COFFLoader without recompiling.
 *
 * Built off of the beacon.h file provided to build for CS.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <stdarg.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>

#include "beacon_compat.h"

#define DEFAULTPROCESSNAME "rundll32.exe"
#ifdef _WIN64
#define X86PATH "SysWOW64"
#define X64PATH "System32"
#else
#define X86PATH "System32"
#define X64PATH "sysnative"
#endif


/* ── Internal function table ─────────────────────────────────────────────
 * Maps Beacon API symbol names to function pointers for COFF relocation.
 * The COFF loader matches __imp_BeaconXxx against these names. */
unsigned char* InternalFunctions[INTERNAL_FUNCTION_COUNT][2] = {
    {(unsigned char*)"BeaconDataParse",               (unsigned char*)BeaconDataParse},
    {(unsigned char*)"BeaconDataInt",                  (unsigned char*)BeaconDataInt},
    {(unsigned char*)"BeaconDataShort",                (unsigned char*)BeaconDataShort},
    {(unsigned char*)"BeaconDataLength",               (unsigned char*)BeaconDataLength},
    {(unsigned char*)"BeaconDataExtract",              (unsigned char*)BeaconDataExtract},
    {(unsigned char*)"BeaconFormatAlloc",              (unsigned char*)BeaconFormatAlloc},
    {(unsigned char*)"BeaconFormatReset",              (unsigned char*)BeaconFormatReset},
    {(unsigned char*)"BeaconFormatFree",               (unsigned char*)BeaconFormatFree},
    {(unsigned char*)"BeaconFormatAppend",             (unsigned char*)BeaconFormatAppend},
    {(unsigned char*)"BeaconFormatPrintf",             (unsigned char*)BeaconFormatPrintf},
    {(unsigned char*)"BeaconFormatToString",           (unsigned char*)BeaconFormatToString},
    {(unsigned char*)"BeaconFormatInt",                (unsigned char*)BeaconFormatInt},
    {(unsigned char*)"BeaconPrintf",                   (unsigned char*)BeaconPrintf},
    {(unsigned char*)"BeaconOutput",                   (unsigned char*)BeaconOutput},
    {(unsigned char*)"BeaconUseToken",                 (unsigned char*)BeaconUseToken},
    {(unsigned char*)"BeaconRevertToken",              (unsigned char*)BeaconRevertToken},
    {(unsigned char*)"BeaconIsAdmin",                  (unsigned char*)BeaconIsAdmin},
    {(unsigned char*)"BeaconGetSpawnTo",               (unsigned char*)BeaconGetSpawnTo},
    {(unsigned char*)"BeaconSpawnTemporaryProcess",    (unsigned char*)BeaconSpawnTemporaryProcess},
    {(unsigned char*)"BeaconInjectProcess",            (unsigned char*)BeaconInjectProcess},
    {(unsigned char*)"BeaconInjectTemporaryProcess",   (unsigned char*)BeaconInjectTemporaryProcess},
    {(unsigned char*)"BeaconCleanupProcess",           (unsigned char*)BeaconCleanupProcess},
    {(unsigned char*)"toWideChar",                     (unsigned char*)toWideChar},
    {(unsigned char*)"LoadLibraryA",                   (unsigned char*)LoadLibraryA},
    {(unsigned char*)"GetProcAddress",                 (unsigned char*)GetProcAddress},
    {(unsigned char*)"GetModuleHandleA",               (unsigned char*)GetModuleHandleA},
    {(unsigned char*)"FreeLibrary",                    (unsigned char*)FreeLibrary},
    {(unsigned char*)"BeaconAddValue",                 (unsigned char*)BeaconAddValue},
    {(unsigned char*)"BeaconGetValue",                 (unsigned char*)BeaconGetValue},
    {(unsigned char*)"BeaconRemoveValue",              (unsigned char*)BeaconRemoveValue},
    {(unsigned char*)"BeaconInformation",              (unsigned char*)BeaconInformation}
};


/* ── Endianness helper ───────────────────────────────────────────────── */

uint32_t swap_endianess(uint32_t indata) {
    uint32_t testint = 0xaabbccdd;
    uint32_t outint = indata;
    if (((unsigned char*)&testint)[0] == 0xdd) {
        ((unsigned char*)&outint)[0] = ((unsigned char*)&indata)[3];
        ((unsigned char*)&outint)[1] = ((unsigned char*)&indata)[2];
        ((unsigned char*)&outint)[2] = ((unsigned char*)&indata)[1];
        ((unsigned char*)&outint)[3] = ((unsigned char*)&indata)[0];
    }
    return outint;
}


/* ── Output control ──────────────────────────────────────────────────── */

int g_suppressStdout = 0;
static int g_callbackErrorCount = 0;

char* beacon_compatibility_output = NULL;
int beacon_compatibility_size = 0;
int beacon_compatibility_offset = 0;


/* ── API call tracing ────────────────────────────────────────────────── */

int g_traceEnabled = 0;
static char* g_traceBuf = NULL;
static int   g_traceLen = 0;
static int   g_traceCap = 0;
static int   g_traceCount = 0;

/* Append a pre-formatted JSON object to the trace buffer.
 * Each entry is a {...} fragment; we add commas between them. */
static void trace_append(const char* entry) {
    if (!g_traceEnabled || !entry) return;
    int entryLen = (int)strlen(entry);
    int needed = entryLen + 2; /* comma + entry */
    if (g_traceLen + needed + 1 > g_traceCap) {
        int newcap = g_traceCap ? g_traceCap * 2 : 4096;
        while (newcap < g_traceLen + needed + 1) newcap *= 2;
        char *p = (char*)realloc(g_traceBuf, newcap);
        if (!p) return;
        g_traceBuf = p;
        g_traceCap = newcap;
    }
    if (g_traceCount > 0) {
        g_traceBuf[g_traceLen++] = ',';
    }
    memcpy(g_traceBuf + g_traceLen, entry, entryLen);
    g_traceLen += entryLen;
    g_traceBuf[g_traceLen] = '\0';
    g_traceCount++;
}

/* Convenience: format + append a trace entry */
static void trace_log(const char* fmt, ...) {
    if (!g_traceEnabled) return;
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    trace_append(buf);
}

char* BeaconGetTraceData(int *outsize) {
    if (!g_traceBuf || g_traceLen == 0) {
        if (outsize) *outsize = 0;
        return NULL;
    }
    /* Wrap in JSON array brackets */
    int total = g_traceLen + 3; /* [ ... ]\0 */
    char *out = (char*)malloc(total);
    if (!out) { if (outsize) *outsize = 0; return NULL; }
    out[0] = '[';
    memcpy(out + 1, g_traceBuf, g_traceLen);
    out[g_traceLen + 1] = ']';
    out[g_traceLen + 2] = '\0';
    if (outsize) *outsize = g_traceLen + 2;
    return out;
}

void BeaconResetTrace(void) {
    if (g_traceBuf) { free(g_traceBuf); g_traceBuf = NULL; }
    g_traceLen = 0;
    g_traceCap = 0;
    g_traceCount = 0;
}


/* ── Data Parsing ────────────────────────────────────────────────────── */

void BeaconDataParse(datap* parser, char* buffer, int size) {
    trace_log("{\"func\":\"BeaconDataParse\",\"size\":%d}", size);
    if (parser == NULL) {
        return;
    }
    memset(parser, 0, sizeof(*parser));
    if (buffer == NULL || size < 4) {
        return;
    }
    parser->original = buffer;
    parser->buffer = buffer;
    parser->length = size - 4;
    parser->size = size - 4;
    parser->buffer += 4;
    return;
}

int BeaconDataInt(datap* parser) {
    if (parser == NULL) {
        return 0;
    }
    int32_t fourbyteint = 0;
    if (parser->length < 4) {
        return 0;
    }
    memcpy(&fourbyteint, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;
    trace_log("{\"func\":\"BeaconDataInt\",\"return\":%d}", (int)fourbyteint);
    return (int)fourbyteint;
}

short BeaconDataShort(datap* parser) {
    if (parser == NULL) {
        return 0;
    }
    int16_t retvalue = 0;
    if (parser->length < 2) {
        return 0;
    }
    memcpy(&retvalue, parser->buffer, 2);
    parser->buffer += 2;
    parser->length -= 2;
    trace_log("{\"func\":\"BeaconDataShort\",\"return\":%d}", (int)retvalue);
    return (short)retvalue;
}

int BeaconDataLength(datap* parser) {
    if (parser == NULL) {
        return 0;
    }
    return parser->length;
}

char* BeaconDataExtract(datap* parser, int* size) {
    if (size != NULL) {
        *size = 0;
    }
    if (parser == NULL) {
        return NULL;
    }
    uint32_t length = 0;
    char* outdata = NULL;
    /* Length prefixed binary blob, uint32_t size prefix. */
    if (parser->length < 4) {
        return NULL;
    }
    memcpy(&length, parser->buffer, 4);
    if (length > (uint32_t)(parser->length - 4)) {
        return NULL;
    }
    parser->buffer += 4;
    outdata = parser->buffer;
    parser->length -= 4;
    parser->length -= length;
    parser->buffer += length;
    if (size != NULL && outdata != NULL) {
        *size = length;
    }
    trace_log("{\"func\":\"BeaconDataExtract\",\"length\":%u}", length);
    return outdata;
}


/* ── Format API ──────────────────────────────────────────────────────── */

void BeaconFormatAlloc(formatp* format, int maxsz) {
    if (format == NULL) {
        return;
    }
    memset(format, 0, sizeof(*format));
    if (maxsz <= 0) {
        return;
    }
    format->original = calloc((size_t)maxsz, 1);
    if (format->original == NULL) {
        return;
    }
    format->buffer = format->original;
    format->length = 0;
    format->size = maxsz;
    return;
}

void BeaconFormatReset(formatp* format) {
    if (format == NULL || format->original == NULL || format->size <= 0) {
        return;
    }
    memset(format->original, 0, (size_t)format->size);
    format->buffer = format->original;
    format->length = 0;
    return;
}

void BeaconFormatFree(formatp* format) {
    if (format == NULL) {
        return;
    }
    if (format->original) {
        free(format->original);
        format->original = NULL;
    }
    format->buffer = NULL;
    format->length = 0;
    format->size = 0;
    return;
}

void BeaconFormatAppend(formatp* format, char* text, int len) {
    if (format == NULL || text == NULL || len < 0
        || format->original == NULL || format->length < 0
        || format->size < format->length
        || len > format->size - format->length) {
        return;
    }
    memcpy(format->buffer, text, len);
    format->buffer += len;
    format->length += len;
    return;
}

void BeaconFormatPrintf(formatp* format, char* fmt, ...) {
    if (format == NULL || fmt == NULL) {
        return;
    }
    va_list args;
    int length = 0;

    va_start(args, fmt);
    length = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    if (length < 0) {
        return;
    }
    if (format->length + length + 1 > format->size) {
        return;
    }

    va_start(args, fmt);
    (void)vsnprintf(format->buffer, length + 1, fmt, args);
    va_end(args);
    format->length += length;
    format->buffer += length;
    return;
}

char* BeaconFormatToString(formatp* format, int* size) {
    if (format == NULL || size == NULL) {
        return NULL;
    }
    *size = format->length;
    return format->original;
}

void BeaconFormatInt(formatp* format, int value) {
    if (format == NULL) {
        return;
    }
    uint32_t indata = value;
    uint32_t outdata = 0;
    if (format->length + 4 > format->size) {
        return;
    }
    outdata = swap_endianess(indata);
    memcpy(format->buffer, &outdata, 4);
    format->length += 4;
    format->buffer += 4;
    return;
}


/* ── Main output functions ───────────────────────────────────────────── */

void BeaconPrintf(int type, char* fmt, ...) {
    if (fmt == NULL) {
        return;
    }

    int length = 0;
    char* tempptr = NULL;
    va_list args;

    if (type == CALLBACK_ERROR) g_callbackErrorCount++;

    /* Trace: capture type + truncated message */
    if (g_traceEnabled) {
        char trbuf[256];
        va_start(args, fmt);
        vsnprintf(trbuf, sizeof(trbuf), fmt, args);
        va_end(args);
        /* Escape quotes/backslashes/newlines for JSON */
        char escaped[300];
        int ei = 0;
        for (int ti = 0; trbuf[ti] && ei < (int)sizeof(escaped) - 2; ti++) {
            char c = trbuf[ti];
            if (c == '"' || c == '\\') { escaped[ei++] = '\\'; escaped[ei++] = c; }
            else if (c == '\n') { escaped[ei++] = '\\'; escaped[ei++] = 'n'; }
            else if (c == '\r') { escaped[ei++] = '\\'; escaped[ei++] = 'r'; }
            else if (c == '\t') { escaped[ei++] = '\\'; escaped[ei++] = 't'; }
            else if ((unsigned char)c >= 0x20) escaped[ei++] = c;
        }
        escaped[ei] = '\0';
        char trentry[512];
        snprintf(trentry, sizeof(trentry),
            "{\"func\":\"BeaconPrintf\",\"type\":%d,\"msg\":\"%.200s\"}", type, escaped);
        trace_append(trentry);
    }

    /* Print to stdout immediately (unless suppressed for JSON mode) */
    if (!g_suppressStdout) {
        va_start(args, fmt);
        vprintf(fmt, args);
        fflush(stdout);
        va_end(args);
    }

    /* Also accumulate in internal buffer */
    va_start(args, fmt);
    length = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    tempptr = realloc(beacon_compatibility_output, beacon_compatibility_size + length + 1);
    if (tempptr == NULL) {
        return;
    }
    beacon_compatibility_output = tempptr;
    memset(beacon_compatibility_output + beacon_compatibility_offset, 0, length + 1);
    va_start(args, fmt);
    length = vsnprintf(beacon_compatibility_output + beacon_compatibility_offset, length + 1, fmt, args);
    beacon_compatibility_size += length;
    beacon_compatibility_offset += length;
    va_end(args);
    return;
}

void BeaconOutput(int type, char* data, int len) {
    if (data == NULL || len <= 0) {
        return;
    }
    if (type == CALLBACK_ERROR) g_callbackErrorCount++;
    trace_log("{\"func\":\"BeaconOutput\",\"type\":%d,\"len\":%d}", type, len);

    /* Print to stdout so output appears inline when piped
     * (unless suppressed for JSON mode). */
    if (!g_suppressStdout) {
        fwrite(data, 1, len, stdout);
        fflush(stdout);
    }

    /* Accumulate in internal buffer */
    char* tempptr = NULL;
    if (beacon_compatibility_size > INT_MAX - len - 1) {
        return;
    }
    tempptr = realloc(beacon_compatibility_output,
                      (size_t)beacon_compatibility_size + len + 1);
    if (tempptr == NULL) {
        return;
    }
    beacon_compatibility_output = tempptr;
    memset(beacon_compatibility_output + beacon_compatibility_offset, 0, len + 1);
    memcpy(beacon_compatibility_output + beacon_compatibility_offset, data, len);
    beacon_compatibility_size += len;
    beacon_compatibility_offset += len;
    return;
}


/* ── Token functions ─────────────────────────────────────────────────── */

BOOL BeaconUseToken(HANDLE token) {
    return SetThreadToken(NULL, token);
}

void BeaconRevertToken(void) {
    if (!RevertToSelf()) {
#ifdef DEBUG
        printf("RevertToSelf Failed!\n");
#endif
    }
    return;
}

BOOL BeaconIsAdmin(void) {
#ifdef DEBUG
    printf("BeaconIsAdmin Called\n");
#endif
    return FALSE;
}


/* ── Injection / spawning stubs ──────────────────────────────────────── */

void BeaconGetSpawnTo(BOOL x86, char* buffer, int length) {
    char* tempBufferPath = NULL;
    if (buffer == NULL) {
        return;
    }
    if (x86) {
        tempBufferPath = "C:\\Windows\\"X86PATH"\\"DEFAULTPROCESSNAME;
    }
    else {
        tempBufferPath = "C:\\Windows\\"X64PATH"\\"DEFAULTPROCESSNAME;
    }

    if (length <= 0 || strlen(tempBufferPath) >= (size_t)length) {
        return;
    }
    memcpy(buffer, tempBufferPath, strlen(tempBufferPath) + 1);
    return;
}

BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO* sInfo, PROCESS_INFORMATION* pInfo) {
    const char* application = x86
        ? "C:\\Windows\\"X86PATH"\\"DEFAULTPROCESSNAME
        : "C:\\Windows\\"X64PATH"\\"DEFAULTPROCESSNAME;
    char command_line[MAX_PATH + 3];
    (void)ignoreToken;
    if (sInfo == NULL || pInfo == NULL) return FALSE;
    if (snprintf(command_line, sizeof(command_line), "\"%s\"", application) < 0)
        return FALSE;
    return CreateProcessA(application, command_line, NULL, NULL, TRUE,
                          CREATE_NO_WINDOW, NULL, NULL, sInfo, pInfo);
}

void BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len, int p_offset, char* arg, int a_len) {
    /* Stub — implement if needed for your BOF. */
    (void)hProc; (void)pid; (void)payload; (void)p_len;
    (void)p_offset; (void)arg; (void)a_len;
    return;
}

void BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len) {
    /* Stub — implement if needed for your BOF. */
    (void)pInfo; (void)payload; (void)p_len;
    (void)p_offset; (void)arg; (void)a_len;
    return;
}

void BeaconCleanupProcess(PROCESS_INFORMATION* pInfo) {
    if (pInfo != NULL) {
        (void)CloseHandle(pInfo->hThread);
        (void)CloseHandle(pInfo->hProcess);
    }
    return;
}

BOOL toWideChar(char* src, wchar_t* dst, int max) {
    if (max < (int)sizeof(wchar_t))
        return FALSE;
    return MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, src, -1, dst, max / sizeof(wchar_t));
}


/* ── Beacon information stub ─────────────────────────────────────────── */

/* Minimal BEACON_INFO for compatibility.  BOFs that call BeaconInformation
 * get local machine info instead of real Beacon metadata. */
typedef struct {
    int  version;           /* fake: 0 */
    int  targetArch;        /* 2 = x64 */
    int  hostArch;          /* 2 = x64 */
    int  osMajor;
    int  osMinor;
    int  osBuild;
    int  pid;
    char computerName[256];
} BEACON_INFO_COMPAT;

void BeaconInformation(void* info, int maxlen) {
    if (info == NULL || maxlen < (int)sizeof(BEACON_INFO_COMPAT)) {
        return;
    }

    BEACON_INFO_COMPAT bi;
    memset(&bi, 0, sizeof(bi));

    bi.version = 0;
#ifdef _WIN64
    bi.targetArch = 2;  /* x64 */
    bi.hostArch = 2;
#else
    bi.targetArch = 1;  /* x86 */
    bi.hostArch = 1;
#endif

    /* Get OS version info */
    OSVERSIONINFOA osvi;
    memset(&osvi, 0, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);
#pragma warning(suppress: 28159 4996) /* Compatibility metadata only. */
    if (GetVersionExA(&osvi)) {
        bi.osMajor = (int)osvi.dwMajorVersion;
        bi.osMinor = (int)osvi.dwMinorVersion;
        bi.osBuild = (int)osvi.dwBuildNumber;
    }

    bi.pid = (int)GetCurrentProcessId();

    /* Computer name */
    DWORD nameLen = sizeof(bi.computerName) - 1;
    GetComputerNameA(bi.computerName, &nameLen);

    memcpy(info, &bi, sizeof(bi));
    return;
}


/* ── Key-Value store ─────────────────────────────────────────────────────
 * Implements BeaconAddValue/GetValue/RemoveValue for BOFs that persist
 * state across subcommand invocations (e.g., inline-psh PS_CTX).
 * Simple linear scan — sufficient for the handful of keys BOFs use. */

#define BEACON_KV_MAX 16
static struct { char* key; void* value; } g_beaconValues[BEACON_KV_MAX];
static int g_beaconValueCount = 0;

BOOL BeaconAddValue(const char* key, void* ptr) {
    trace_log("{\"func\":\"BeaconAddValue\",\"key\":\"%s\",\"ptr\":\"0x%llX\"}",
              key ? key : "(null)", (unsigned long long)(uintptr_t)ptr);
    if (key == NULL) return FALSE;
    /* Update existing key */
    for (int i = 0; i < g_beaconValueCount; i++) {
        if (strcmp(g_beaconValues[i].key, key) == 0) {
            g_beaconValues[i].value = ptr;
            return TRUE;
        }
    }
    /* Add new key */
    if (g_beaconValueCount >= BEACON_KV_MAX) return FALSE;
    g_beaconValues[g_beaconValueCount].key = _strdup(key);
    g_beaconValues[g_beaconValueCount].value = ptr;
    g_beaconValueCount++;
    return TRUE;
}

void* BeaconGetValue(const char* key) {
    if (key == NULL) return NULL;
    for (int i = 0; i < g_beaconValueCount; i++) {
        if (strcmp(g_beaconValues[i].key, key) == 0) {
            trace_log("{\"func\":\"BeaconGetValue\",\"key\":\"%s\",\"return\":\"0x%llX\"}",
                      key, (unsigned long long)(uintptr_t)g_beaconValues[i].value);
            return g_beaconValues[i].value;
        }
    }
    trace_log("{\"func\":\"BeaconGetValue\",\"key\":\"%s\",\"return\":null}", key);
    return NULL;
}

BOOL BeaconRemoveValue(const char* key) {
    trace_log("{\"func\":\"BeaconRemoveValue\",\"key\":\"%s\"}", key ? key : "(null)");
    if (key == NULL) return FALSE;
    for (int i = 0; i < g_beaconValueCount; i++) {
        if (strcmp(g_beaconValues[i].key, key) == 0) {
            free(g_beaconValues[i].key);
            g_beaconValues[i] = g_beaconValues[--g_beaconValueCount];
            return TRUE;
        }
    }
    return FALSE;
}


/* ── Output buffer management ────────────────────────────────────────── */

char* BeaconGetOutputData(int* outsize) {
    if (outsize == NULL) {
        return NULL;
    }
    char* outdata = beacon_compatibility_output;
    *outsize = beacon_compatibility_size;
    beacon_compatibility_output = NULL;
    beacon_compatibility_size = 0;
    beacon_compatibility_offset = 0;
    return outdata;
}

void BeaconResetOutput(void) {
    if (beacon_compatibility_output != NULL) {
        free(beacon_compatibility_output);
        beacon_compatibility_output = NULL;
    }
    beacon_compatibility_size = 0;
    beacon_compatibility_offset = 0;
    g_callbackErrorCount = 0;
}

int BeaconGetErrorCount(void) {
    return g_callbackErrorCount;
}

#endif /* _WIN32 */
