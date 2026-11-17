/* Regression fixture: MinGW direct calls to bare CRT symbols. */
extern void *malloc(unsigned long long size);
extern void free(void *ptr);
extern void *memset(void *ptr, int value, unsigned long long size);

__declspec(dllimport) void BeaconPrintf(int type, char *format, ...);

void go(char *args, int len) {
    void *allocation;
    (void)args;
    (void)len;

    allocation = malloc(32);
    if (allocation != 0) {
        memset(allocation, 0x41, 32);
        free(allocation);
    }

    BeaconPrintf(0, "bare-function:%s\n", allocation ? "ok" : "failed");
}
