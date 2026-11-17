#include <windows.h>

/* A native helper with registered unwind metadata.  The test BOF calls this
 * while the loader's VEH is active.  Returning CONTINUE_SEARCH from the VEH
 * must allow this frame-based handler to consume the software exception. */
__declspec(dllexport) void RaiseSoftwareException(void)
{
    RaiseException(0x000006BAu, 0, 0, NULL);
}
