#include <windows.h>

__declspec(dllimport) void BeaconPrintf(int type, char *fmt, ...);
__declspec(dllimport) void EXCEPTION_HELPER$RaiseSoftwareException(void);

#define CALLBACK_OUTPUT 0x0
#define RPC_S_SERVER_UNAVAILABLE_CODE 0x000006BAul

void go(char *args, int len)
{
    unsigned long code;
    (void)args;
    (void)len;

    code = 0;
    __try {
        EXCEPTION_HELPER$RaiseSoftwareException();
    }
    __except ((code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)) {
    }
    if (code == RPC_S_SERVER_UNAVAILABLE_CODE) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "software-exception:handled:0x%08lX\n", code);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "software-exception:unexpected:0x%08lX\n", code);
    }
}
