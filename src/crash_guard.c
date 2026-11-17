#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include "crash_guard.h"

#ifdef _WIN32
static volatile int g_active = 0;
static volatile int g_returned_from_fault = 0;
static volatile DWORD g_code = 0;
static volatile uintptr_t g_instruction_address = 0;
static volatile DWORD g_parameter_count = 0;
static ULONG_PTR g_parameters[EXCEPTION_MAXIMUM_PARAMETERS];
static CONTEXT g_saved_context;
static PVOID g_handler = NULL;

static int is_recoverable_fault(DWORD code) {
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_IN_PAGE_ERROR:
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_PRIV_INSTRUCTION:
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_INT_OVERFLOW:
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
    case EXCEPTION_DATATYPE_MISALIGNMENT:
    case EXCEPTION_FLT_DENORMAL_OPERAND:
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
    case EXCEPTION_FLT_INEXACT_RESULT:
    case EXCEPTION_FLT_INVALID_OPERATION:
    case EXCEPTION_FLT_OVERFLOW:
    case EXCEPTION_FLT_STACK_CHECK:
    case EXCEPTION_FLT_UNDERFLOW:
        return 1;
    default:
        return 0;
    }
}

static LONG CALLBACK crash_handler(EXCEPTION_POINTERS* pointers) {
    DWORD code;

    if (!g_active) return EXCEPTION_CONTINUE_SEARCH;
    code = pointers->ExceptionRecord->ExceptionCode;
    if (!is_recoverable_fault(code)) return EXCEPTION_CONTINUE_SEARCH;

    g_code = code;
    g_instruction_address =
        (uintptr_t)pointers->ExceptionRecord->ExceptionAddress;
    g_parameter_count = pointers->ExceptionRecord->NumberParameters;
    if (g_parameter_count > EXCEPTION_MAXIMUM_PARAMETERS)
        g_parameter_count = EXCEPTION_MAXIMUM_PARAMETERS;
    for (DWORD index = 0; index < g_parameter_count; index++) {
        g_parameters[index] =
            pointers->ExceptionRecord->ExceptionInformation[index];
    }
    g_active = 0;
    g_returned_from_fault = 1;
    *pointers->ContextRecord = g_saved_context;
    return EXCEPTION_CONTINUE_EXECUTION;
}
#endif

int CrashGuardInstall(void) {
#ifdef _WIN32
    if (g_handler != NULL) return 1;
    g_handler = AddVectoredExceptionHandler(1, crash_handler);
    return g_handler != NULL;
#else
    return 1;
#endif
}

void CrashGuardRemove(void) {
#ifdef _WIN32
    if (g_handler != NULL) {
        RemoveVectoredExceptionHandler(g_handler);
        g_handler = NULL;
    }
#endif
}

int CrashGuardExecute(coff_entry_fn entry, char* arguments,
                      unsigned long argument_size, CrashDetails* details) {
    if (details == NULL || entry == NULL) return 0;
    memset(details, 0, sizeof(*details));
#ifdef _WIN32
    g_code = 0;
    g_instruction_address = 0;
    g_parameter_count = 0;
    g_returned_from_fault = 0;
    memset(g_parameters, 0, sizeof(g_parameters));

    RtlCaptureContext(&g_saved_context);
    if (!g_returned_from_fault) {
        g_active = 1;
        entry(arguments, argument_size);
        g_active = 0;
        return 0;
    }

    details->code = g_code;
    details->instructionAddress = g_instruction_address;
    details->parameterCount = g_parameter_count;
    for (DWORD index = 0; index < g_parameter_count; index++)
        details->parameters[index] = (uintptr_t)g_parameters[index];
    return 1;
#else
    entry(arguments, argument_size);
    return 0;
#endif
}

const char* CrashExceptionName(uint32_t code) {
#ifdef _WIN32
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION: return "EXCEPTION_ACCESS_VIOLATION";
    case EXCEPTION_IN_PAGE_ERROR: return "EXCEPTION_IN_PAGE_ERROR";
    case EXCEPTION_ILLEGAL_INSTRUCTION: return "EXCEPTION_ILLEGAL_INSTRUCTION";
    case EXCEPTION_PRIV_INSTRUCTION: return "EXCEPTION_PRIV_INSTRUCTION";
    case EXCEPTION_INT_DIVIDE_BY_ZERO: return "EXCEPTION_INT_DIVIDE_BY_ZERO";
    case EXCEPTION_INT_OVERFLOW: return "EXCEPTION_INT_OVERFLOW";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
    case EXCEPTION_DATATYPE_MISALIGNMENT: return "EXCEPTION_DATATYPE_MISALIGNMENT";
    case EXCEPTION_FLT_DENORMAL_OPERAND: return "EXCEPTION_FLT_DENORMAL_OPERAND";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO: return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
    case EXCEPTION_FLT_INEXACT_RESULT: return "EXCEPTION_FLT_INEXACT_RESULT";
    case EXCEPTION_FLT_INVALID_OPERATION: return "EXCEPTION_FLT_INVALID_OPERATION";
    case EXCEPTION_FLT_OVERFLOW: return "EXCEPTION_FLT_OVERFLOW";
    case EXCEPTION_FLT_STACK_CHECK: return "EXCEPTION_FLT_STACK_CHECK";
    case EXCEPTION_FLT_UNDERFLOW: return "EXCEPTION_FLT_UNDERFLOW";
    default: return "UNKNOWN_EXCEPTION";
    }
#else
    (void)code;
    return "UNKNOWN_EXCEPTION";
#endif
}

int CrashHasMemoryAccess(const CrashDetails* details) {
#ifdef _WIN32
    return details != NULL && details->parameterCount >= 2
        && (details->code == EXCEPTION_ACCESS_VIOLATION
            || details->code == EXCEPTION_IN_PAGE_ERROR);
#else
    (void)details;
    return 0;
#endif
}

const char* CrashAccessType(const CrashDetails* details) {
    uintptr_t operation;
    if (!CrashHasMemoryAccess(details)) return "unknown";
    operation = details->parameters[0];
    if (operation == 0) return "read";
    if (operation == 1) return "write";
    if (operation == 8) return "execute";
    return "unknown";
}

uintptr_t CrashAccessAddress(const CrashDetails* details) {
    return CrashHasMemoryAccess(details) ? details->parameters[1] : 0;
}

uintptr_t CrashInPageStatus(const CrashDetails* details) {
#ifdef _WIN32
    if (details != NULL && details->code == EXCEPTION_IN_PAGE_ERROR
        && details->parameterCount >= 3) {
        return details->parameters[2];
    }
#else
    (void)details;
#endif
    return 0;
}
