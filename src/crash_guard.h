#ifndef CRASH_GUARD_H_
#define CRASH_GUARD_H_

#include <stdint.h>

#include "coffloader.h"

#define CRASH_MAX_PARAMETERS 15

typedef struct _CrashDetails {
    uint32_t code;
    uintptr_t instructionAddress;
    uint32_t parameterCount;
    uintptr_t parameters[CRASH_MAX_PARAMETERS];
} CrashDetails;

int CrashGuardInstall(void);
void CrashGuardRemove(void);
int CrashGuardExecute(coff_entry_fn entry, char* arguments,
                      unsigned long argument_size, CrashDetails* details);

const char* CrashExceptionName(uint32_t code);
int CrashHasMemoryAccess(const CrashDetails* details);
const char* CrashAccessType(const CrashDetails* details);
uintptr_t CrashAccessAddress(const CrashDetails* details);
uintptr_t CrashInPageStatus(const CrashDetails* details);

#endif
