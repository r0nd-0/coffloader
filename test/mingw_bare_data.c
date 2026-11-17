/* Regression fixture: a bare CRT data export must never become a thunk. */
extern int __argc;

__declspec(dllimport) void BeaconPrintf(int type, char *format, ...);

void go(char *args, int len) {
    (void)args;
    (void)len;
    BeaconPrintf(0, "bare-data __argc=%d\n", __argc);
}
