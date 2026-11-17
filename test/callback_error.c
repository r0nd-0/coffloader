#define CALLBACK_ERROR 0x0d

__declspec(dllimport) void BeaconPrintf(int type, const char *fmt, ...);

void go(char *args, unsigned long len) {
    (void)args;
    (void)len;
    BeaconPrintf(CALLBACK_ERROR, "expected callback failure");
}
