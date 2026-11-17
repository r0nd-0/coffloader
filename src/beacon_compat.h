/*
 * beacon_compat.h — Cobalt Strike 4.X BOF Compatibility Layer
 * ------------------------------------------------------------
 * Provides Beacon API function declarations so that BOFs compiled for
 * Cobalt Strike can run inside COFFLoader without recompiling.
 *
 * Built off of the beacon.h file provided to build for CS.
 */
#ifndef BEACON_COMPAT_H_
#define BEACON_COMPAT_H_

#include <stdint.h>

/* ── Internal function table ─────────────────────────────────────────────
 * Resolved by the COFF loader when a BOF imports __imp_Beacon* symbols.
 * 31 slots: [name_string, function_pointer] pairs. */
#define INTERNAL_FUNCTION_COUNT 31
extern unsigned char* InternalFunctions[INTERNAL_FUNCTION_COUNT][2];

/* ── Data parsing (datap) ────────────────────────────────────────────── */
typedef struct {
    char * original; /* the original buffer [so we can free it] */
    char * buffer;   /* current pointer into our buffer */
    int    length;   /* remaining length of data */
    int    size;     /* total size of this buffer */
} datap;

void    BeaconDataParse(datap * parser, char * buffer, int size);
int     BeaconDataInt(datap * parser);
short   BeaconDataShort(datap * parser);
int     BeaconDataLength(datap * parser);
char *  BeaconDataExtract(datap * parser, int * size);

/* ── Format buffer (formatp) ─────────────────────────────────────────── */
typedef struct {
    char * original; /* the original buffer [so we can free it] */
    char * buffer;   /* current pointer into our buffer */
    int    length;   /* remaining length of data */
    int    size;     /* total size of this buffer */
} formatp;

void    BeaconFormatAlloc(formatp * format, int maxsz);
void    BeaconFormatReset(formatp * format);
void    BeaconFormatFree(formatp * format);
void    BeaconFormatAppend(formatp * format, char * text, int len);
void    BeaconFormatPrintf(formatp * format, char * fmt, ...);
char *  BeaconFormatToString(formatp * format, int * size);
void    BeaconFormatInt(formatp * format, int value);

/* ── Output callback types ───────────────────────────────────────────── */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

/* ── Output functions ────────────────────────────────────────────────── */
void   BeaconPrintf(int type, char * fmt, ...);
void   BeaconOutput(int type, char * data, int len);

/* ── Token functions ─────────────────────────────────────────────────── */
BOOL   BeaconUseToken(HANDLE token);
void   BeaconRevertToken(void);
BOOL   BeaconIsAdmin(void);

/* ── Spawn + Inject functions ────────────────────────────────────────── */
void   BeaconGetSpawnTo(BOOL x86, char * buffer, int length);
BOOL   BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO * sInfo, PROCESS_INFORMATION * pInfo);
void   BeaconInjectProcess(HANDLE hProc, int pid, char * payload, int p_len, int p_offset, char * arg, int a_len);
void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION * pInfo, char * payload, int p_len, int p_offset, char * arg, int a_len);
void   BeaconCleanupProcess(PROCESS_INFORMATION * pInfo);

/* ── Utility functions ───────────────────────────────────────────────── */
BOOL     toWideChar(char * src, wchar_t * dst, int max);
uint32_t swap_endianess(uint32_t indata);

/* ── Beacon information ──────────────────────────────────────────────── */
void   BeaconInformation(void* info, int maxlen);

/* ── Key-Value store ─────────────────────────────────────────────────── */
BOOL   BeaconAddValue(const char* key, void* ptr);
void*  BeaconGetValue(const char* key);
BOOL   BeaconRemoveValue(const char* key);

/* ── Output control (used by the harness, not by BOFs) ──────────────── */
/* Set to 1 to suppress BeaconPrintf/BeaconOutput stdout printing.
 * Output is still accumulated in the buffer for BeaconGetOutputData. */
extern int g_suppressStdout;

/* ── API call tracing ───────────────────────────────────────────────── */
/* Set to 1 to log every Beacon API call to the trace buffer.
 * Trace data is a JSON array of call records. */
extern int g_traceEnabled;
char*  BeaconGetOutputData(int *outsize);
void   BeaconResetOutput(void);
int    BeaconGetErrorCount(void);

/* Trace data: returns a JSON array string of API call records. Caller frees. */
char*  BeaconGetTraceData(int *outsize);
void   BeaconResetTrace(void);

#endif /* BEACON_COMPAT_H_ */
