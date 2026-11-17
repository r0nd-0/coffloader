/*
 * crashtest.c — Test BOF that deliberately crashes for crash resolution testing.
 *
 * Build: cl /c /GS- /Fo:test\crashtest.x64.o test\crashtest.c
 *
 * Subcommands via first int arg:
 *   0 = Print "hello" and return normally
 *   1 = Null pointer dereference (read)
 *   2 = Call through function pointer that does the crash (tests symbol resolution)
 */

/* Minimal Beacon API declarations */
__declspec(dllimport) void BeaconPrintf(int type, char *fmt, ...);

typedef struct { char *original; char *buffer; int length; int size; } datap;
__declspec(dllimport) void BeaconDataParse(datap *parser, char *buffer, int size);
__declspec(dllimport) int  BeaconDataInt(datap *parser);

#define CALLBACK_OUTPUT 0x0

/* This function will show up in crash resolution */
void crashy_function(void) {
    volatile int *p = (volatile int *)0;
    *p = 0xDEAD;  /* NULL pointer write → access violation */
}

/* Another function to test offset resolution */
void do_some_work(int subcmd) {
    if (subcmd == 1) {
        /* Direct null deref */
        volatile int *p = (volatile int *)0;
        int x = *p;  /* NULL pointer read → access violation */
        (void)x;
    } else if (subcmd == 2) {
        /* Crash via named function */
        crashy_function();
    }
}

void go(char *args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    int subcmd = BeaconDataInt(&parser);

    BeaconPrintf(CALLBACK_OUTPUT, "[crashtest] subcmd=%d\n", subcmd);

    if (subcmd == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[crashtest] hello, no crash\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[crashtest] about to crash...\n");
        do_some_work(subcmd);
        BeaconPrintf(CALLBACK_OUTPUT, "[crashtest] survived (shouldn't see this)\n");
    }
}
