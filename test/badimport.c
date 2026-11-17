/*
 * badimport.c — Test BOF with deliberately broken DFR imports.
 *
 * Build: cl /c /GS- /Od /Fo:test\badimport.x64.o test\badimport.c
 *
 * Has three bad imports:
 *   1. NTDLL$RtlGetVersion — NTDLL won't load (needs "ntdll" lowercase or full name)
 *   2. KERNEL32$FakeFunction — function doesn't exist
 *   3. BOGUSLIB$DoStuff — library doesn't exist
 */

/* Good import — this will resolve fine */
__declspec(dllimport) void BeaconPrintf(int type, char *fmt, ...);

typedef struct { char *original; char *buffer; int length; int size; } datap;
__declspec(dllimport) void BeaconDataParse(datap *parser, char *buffer, int size);
__declspec(dllimport) int  BeaconDataInt(datap *parser);

/* Bad imports — these should all fail to resolve */
__declspec(dllimport) int  NTDLL$RtlGetVersion(void *);
__declspec(dllimport) int  KERNEL32$FakeFunction(int);
__declspec(dllimport) void BOGUSLIB$DoStuff(void);

#define CALLBACK_OUTPUT 0x0

void go(char *args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    int x = BeaconDataInt(&parser);

    BeaconPrintf(CALLBACK_OUTPUT, "[badimport] started with %d\n", x);

    /* These calls would crash if imports weren't validated */
    NTDLL$RtlGetVersion((void*)0);
    KERNEL32$FakeFunction(42);
    BOGUSLIB$DoStuff();

    BeaconPrintf(CALLBACK_OUTPUT, "[badimport] done\n");
}
