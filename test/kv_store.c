typedef int BOOL;

#define CALLBACK_OUTPUT 0

__declspec(dllimport) BOOL BeaconAddValue(const char *key, void *ptr);
__declspec(dllimport) void *BeaconGetValue(const char *key);
__declspec(dllimport) BOOL BeaconRemoveValue(const char *key);
__declspec(dllimport) void BeaconPrintf(int type, const char *fmt, ...);

void go(char *args, unsigned long len) {
    static int value = 42;
    (void)args;
    (void)len;

    if (!BeaconAddValue("kv-regression", &value)) {
        BeaconPrintf(CALLBACK_OUTPUT, "kv-store:add-failed");
        return;
    }
    if (BeaconGetValue("kv-regression") != &value) {
        BeaconPrintf(CALLBACK_OUTPUT, "kv-store:get-failed");
        return;
    }
    if (!BeaconRemoveValue("kv-regression")) {
        BeaconPrintf(CALLBACK_OUTPUT, "kv-store:remove-failed");
        return;
    }
    if (BeaconGetValue("kv-regression") != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "kv-store:stale-value");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "kv-store:ok");
}
