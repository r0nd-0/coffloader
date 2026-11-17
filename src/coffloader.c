/*
 * coffloader.c — General-Purpose COFF/BOF Loader (core)
 * -----------------------------------------------------
 * Loads, relocates, and resolves entry functions in COFF object files
 * produced by MSVC or MinGW for Cobalt Strike BOF consumption.
 *
 * Key fixes over the original TrustedSec COFFLoader:
 *   - Contiguous VirtualAlloc for all sections + GOT (REL32 overflow fix)
 *   - __ImageBase special-case in process_symbol (MSVC jump table fix)
 *   - String-table-aware symbol lookup (long symbol names)
 *   - Auxiliary symbol entry skipping (prevents OOB reads)
 *   - CoffLoad/CoffFree split for multi-command mode
 *   - Typed MinGW bare-symbol dispatch (function thunk vs. data export)
 *   - Checked COFF spans and fail-closed relocation handling
 *   - Writable-load / executable-read final page protections
 *   - Validated x64 .pdata registration and teardown
 *
 * No main() here — see main.c for the CLI entry point.
 */
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#if defined(_WIN32)
#include <windows.h>
#include "beacon_compat.h"
#endif

#include "coffloader.h"

/* ── Debug output ───────────────────────────────────────────────────────── */
#ifdef DEBUG
#define DEBUG_PRINT(x, ...) printf(x, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(x, ...)
#endif

/* ── Architecture-dependent import prefix ───────────────────────────────── */
#if defined(__x86_64__) || defined(_WIN64)
#define PREPENDSYMBOLVALUE "__imp_"
#else
#define PREPENDSYMBOLVALUE "__imp__"
#endif

#define COFFLOADER_RETURN_VAL_IF(expr, val, fmt, ...) \
    if ((expr)) { DEBUG_PRINT(fmt, ##__VA_ARGS__); return val; }

#define COFFLOADER_FAIL_IF(expr, handle, phase, code, message) \
    if ((expr)) { return coff_fail(handle, phase, code, message); }

static bool coff_range_valid(size_t file_size, size_t offset, size_t length) {
    return offset <= file_size && length <= file_size - offset;
}

static bool coff_array_range_valid(size_t file_size, size_t offset,
                                   size_t count, size_t element_size) {
    if (element_size != 0 && count > SIZE_MAX / element_size) {
        return false;
    }
    return coff_range_valid(file_size, offset, count * element_size);
}

static const char* coff_get_symbol_name(const coff_sym_t* symbol,
                                        const char* string_table,
                                        uint32_t string_table_size,
                                        char short_name[9]) {
    if (symbol->first.value[0] == 0) {
        uint32_t offset = symbol->first.value[1];
        if (offset < sizeof(uint32_t) || offset >= string_table_size) {
            return NULL;
        }
        if (memchr(string_table + offset, '\0', string_table_size - offset) == NULL) {
            return NULL;
        }
        return string_table + offset;
    }

    memcpy(short_name, symbol->first.Name, 8);
    short_name[8] = '\0';
    return short_name;
}

static void coff_copy_section_name(const coff_sect_t* section,
                                   const char* string_table,
                                   uint32_t string_table_size,
                                   char* output, size_t output_size) {
    char inline_name[9] = {0};
    const char *name = inline_name;

    if (output == NULL || output_size == 0) return;
    output[0] = '\0';
    memcpy(inline_name, section->Name, 8);

    if (inline_name[0] == '/' && inline_name[1] >= '0'
        && inline_name[1] <= '9') {
        char *end = NULL;
        unsigned long offset = strtoul(inline_name + 1, &end, 10);
        if (end != inline_name + 1 && *end == '\0'
            && offset >= sizeof(uint32_t) && offset < string_table_size
            && memchr(string_table + offset, '\0',
                      string_table_size - offset) != NULL) {
            name = string_table + offset;
        }
    }

    strncpy(output, name, output_size - 1);
    output[output_size - 1] = '\0';
}

static int coff_fail(CoffHandle* handle, const char* phase,
                     const char* code, const char* message) {
    if (handle != NULL) {
        strncpy(handle->errorPhase, phase ? phase : "load",
                sizeof(handle->errorPhase) - 1);
        strncpy(handle->errorCode, code ? code : "COFF_LOAD_FAILED",
                sizeof(handle->errorCode) - 1);
        strncpy(handle->errorMessage, message ? message : "COFF load failed",
                sizeof(handle->errorMessage) - 1);
    }
    DEBUG_PRINT("%s: %s\n", code ? code : "COFF_LOAD_FAILED",
                message ? message : "COFF load failed");
    return 1;
}

static void record_import(CoffHandle* handle, const char* symbol,
                          const char* provider, const char* dispatch,
                          void* address, int resolved) {
    int index;
    if (handle == NULL || symbol == NULL) return;

    for (index = 0; index < handle->importCount; index++) {
        if (strcmp(handle->imports[index].symbol, symbol) == 0
            && strcmp(handle->imports[index].dispatch, dispatch) == 0) {
            return;
        }
    }
    if (handle->importCount >= 256) return;
    if (handle->imports == NULL) {
        handle->imports = (CoffImportInfo*)calloc(256, sizeof(CoffImportInfo));
        if (handle->imports == NULL) return;
    }

    index = handle->importCount++;
    strncpy(handle->imports[index].symbol, symbol,
            sizeof(handle->imports[index].symbol) - 1);
    if (provider != NULL) {
        strncpy(handle->imports[index].provider, provider,
                sizeof(handle->imports[index].provider) - 1);
    }
    strncpy(handle->imports[index].dispatch, dispatch,
            sizeof(handle->imports[index].dispatch) - 1);
    handle->imports[index].address = (uintptr_t)address;
    handle->imports[index].resolved = resolved;
}

static int build_section_info(CoffHandle* handle, const unsigned char* coff_data,
                              const coff_file_header_t* header,
                              char** section_mapping, const char* string_table,
                              uint32_t string_table_size) {
    handle->sectionCount = header->NumberOfSections;
    handle->sections = (CoffSectionInfo*)calloc(
        handle->sectionCount, sizeof(CoffSectionInfo));
    if (handle->sections == NULL) {
        return coff_fail(handle, "load", "COFF_METADATA_ALLOCATION_FAILED",
                         "Failed to allocate section metadata");
    }

    for (int index = 0; index < handle->sectionCount; index++) {
        coff_sect_t *section = (coff_sect_t*)(coff_data
            + sizeof(coff_file_header_t) + sizeof(coff_sect_t) * index);
        coff_copy_section_name(section, string_table, string_table_size,
            handle->sections[index].name,
            sizeof(handle->sections[index].name));
        handle->sections[index].start = (uintptr_t)section_mapping[index];
        handle->sections[index].size = section->SizeOfRawData;
        handle->sections[index].characteristics = section->Characteristics;
        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            strcpy_s(handle->sections[index].protection,
                     sizeof(handle->sections[index].protection), "RX");
        } else if (section->Characteristics & IMAGE_SCN_MEM_WRITE) {
            strcpy_s(handle->sections[index].protection,
                     sizeof(handle->sections[index].protection), "RW");
        } else {
            strcpy_s(handle->sections[index].protection,
                     sizeof(handle->sections[index].protection), "R");
        }
    }
    return 0;
}

static int compare_symbol_addresses(const void* left, const void* right) {
    const CoffSymEntry* first = (const CoffSymEntry*)left;
    const CoffSymEntry* second = (const CoffSymEntry*)right;
    if (first->addr < second->addr) return -1;
    if (first->addr > second->addr) return 1;
    return 0;
}

#if defined(_WIN32) && defined(_WIN64)
static void unregister_unwind_tables(CoffHandle* handle) {
    int index;

    if (handle == NULL || handle->unwindRegistrations == NULL) return;
    for (index = handle->unwindRegistrationCount - 1; index >= 0; index--) {
        PRUNTIME_FUNCTION table =
            (PRUNTIME_FUNCTION)handle->unwindRegistrations[index].table;
        if (table != NULL) {
            (void)RtlDeleteFunctionTable(table);
        }
    }
    free(handle->unwindRegistrations);
    handle->unwindRegistrations = NULL;
    handle->unwindRegistrationCount = 0;
    handle->unwindFunctionCount = 0;
}

static int register_unwind_tables(CoffHandle* handle, char** section_mapping,
                                  char* image_base, size_t image_size) {
    int index;

    handle->unwindRegistrations = (CoffUnwindRegistration*)calloc(
        (size_t)handle->sectionCount, sizeof(CoffUnwindRegistration));
    if (handle->unwindRegistrations == NULL) {
        return coff_fail(handle, "unwind", "COFF_UNWIND_ALLOCATION_FAILED",
                         "Failed to allocate unwind registration metadata");
    }

    for (index = 0; index < handle->sectionCount; index++) {
        const CoffSectionInfo* section = &handle->sections[index];
        PRUNTIME_FUNCTION table;
        DWORD entry_count;
        DWORD entry_index;

        if (strcmp(section->name, ".pdata") != 0
            && strncmp(section->name, ".pdata$", 7) != 0) {
            continue;
        }
        handle->pdataSectionCount++;
        if (section->size == 0) continue;
        if (section->size % sizeof(RUNTIME_FUNCTION) != 0) {
            unregister_unwind_tables(handle);
            return coff_fail(handle, "unwind", "COFF_PDATA_SIZE_INVALID",
                             ".pdata size is not a RUNTIME_FUNCTION multiple");
        }
        if (section->size / sizeof(RUNTIME_FUNCTION) > MAXDWORD) {
            unregister_unwind_tables(handle);
            return coff_fail(handle, "unwind", "COFF_PDATA_COUNT_INVALID",
                             ".pdata contains too many function entries");
        }

        table = (PRUNTIME_FUNCTION)section_mapping[index];
        entry_count = (DWORD)(section->size / sizeof(RUNTIME_FUNCTION));
        for (entry_index = 0; entry_index < entry_count; entry_index++) {
            DWORD begin = table[entry_index].BeginAddress;
            DWORD end = table[entry_index].EndAddress;
            DWORD unwind = table[entry_index].UnwindData & ~3u;

            if (begin >= end || (size_t)end > image_size
                || unwind == 0 || (size_t)unwind >= image_size
                || (entry_index > 0
                    && table[entry_index - 1].BeginAddress > begin)) {
                unregister_unwind_tables(handle);
                return coff_fail(handle, "unwind", "COFF_PDATA_ENTRY_INVALID",
                                 ".pdata contains an invalid runtime function entry");
            }
        }

        if (!RtlAddFunctionTable(table, entry_count, (DWORD64)image_base)) {
            unregister_unwind_tables(handle);
            return coff_fail(handle, "unwind", "COFF_UNWIND_REGISTRATION_FAILED",
                             "RtlAddFunctionTable rejected COFF unwind metadata");
        }

        handle->unwindRegistrations[handle->unwindRegistrationCount].table = table;
        handle->unwindRegistrations[handle->unwindRegistrationCount].entryCount =
            entry_count;
        handle->unwindRegistrationCount++;
        handle->unwindFunctionCount += entry_count;
    }

    if (handle->unwindRegistrationCount == 0) {
        free(handle->unwindRegistrations);
        handle->unwindRegistrations = NULL;
    }
    return 0;
}
#endif

/* Global set by CoffLoad to the first section's base address.
 * Used by process_symbol to resolve __ImageBase for REL32 relocations
 * so the 32-bit delta stays within range. */
static void* g_coffImageBase = NULL;
static void* g_cSpecificHandler = NULL;

/* ── COMDAT / unresolved symbol diagnostics ────────────────────────────── */

/* Classify an unresolved symbol and provide a fix suggestion.
 * kind: 0=missing DFR, 1=COMDAT GUID/IID, 2=RTTI, 3=string pool, 4=unknown */
static void diagnose_unresolved(const char* sym, CoffUnresolvedImport* ui) {
    /* RTTI symbols: ??_R0, ??_R1, ??_R2, ??_R3, ??_R4 */
    if (strstr(sym, "??_R0") || strstr(sym, "??_R1") ||
        strstr(sym, "??_R2") || strstr(sym, "??_R3") || strstr(sym, "??_R4")) {
        ui->kind = 2;
        strncpy(ui->diagnostic, "RTTI metadata — compile with /GR- to disable", sizeof(ui->diagnostic) - 1);
        return;
    }
    /* String pool COMDAT: ??_C@_ (MSVC pooled string literal) */
    if (strstr(sym, "??_C@_")) {
        ui->kind = 3;
        strncpy(ui->diagnostic, "Pooled string literal — compile with /GF- to disable string pooling", sizeof(ui->diagnostic) - 1);
        return;
    }
    /* GUID/IID COMDAT: contains "IID_" or "GUID" or "CLSID_" in the symbol */
    if (strstr(sym, "IID_") || strstr(sym, "GUID") || strstr(sym, "CLSID_") ||
        strstr(sym, "DIID_") || strstr(sym, "LIBID_")) {
        ui->kind = 1;
        strncpy(ui->diagnostic,
            "COMDAT GUID — use stack-init pattern instead of static const GUID / EXTERN_GUID. "
            "Add #undef EXTERN_GUID before Windows headers",
            sizeof(ui->diagnostic) - 1);
        return;
    }
    /* __imp_ prefix but not MODULE$Function — missing DFR */
    if (strncmp(sym, "__imp_", 6) == 0) {
        const char* after = sym + 6;
        const char* dollar = strchr(after, '$');
        if (dollar) {
            /* Has MODULE$Function format — standard DFR miss */
            ui->kind = 0;
            char lib[64] = {0}, func[128] = {0};
            size_t liblen = (size_t)(dollar - after);
            if (liblen > 63) liblen = 63;
            strncpy(lib, after, liblen);
            strncpy(func, dollar + 1, sizeof(func) - 1);
            lib[liblen] = '\0';
            func[sizeof(func) - 1] = '\0';
            /* Trim @N suffix from stdcall */
            char *at = strchr(func, '@');
            if (at) *at = '\0';
            snprintf(ui->diagnostic, sizeof(ui->diagnostic),
                "Add to dfr_imports.h: DFR(%s, %s); #define %s %s$%s",
                lib, func, func, lib, func);
        } else {
            ui->kind = 0;
            snprintf(ui->diagnostic, sizeof(ui->diagnostic),
                "Missing import — add DFR macro for: %s", after);
        }
        return;
    }
    /* C++ mangled but not RTTI/GUID — likely COMDAT from static const or template */
    if (sym[0] == '?' && sym[1] == '?') {
        ui->kind = 4;
        strncpy(ui->diagnostic,
            "C++ COMDAT symbol — likely from static const data, template, or inline function. "
            "Use stack-initialized variables instead of static const aggregates",
            sizeof(ui->diagnostic) - 1);
        return;
    }
    /* Fallback */
    ui->kind = 4;
    strncpy(ui->diagnostic, "Unknown external — check if this symbol needs a DFR import or is a COMDAT artifact", sizeof(ui->diagnostic) - 1);
}

/* ── Helper: string prefix check ────────────────────────────────────────── */
static BOOL starts_with(const char* string, const char* substring) {
    return strncmp(string, substring, strlen(substring)) == 0;
}

static bool import_name_matches(const char* decorated, const char* expected) {
    size_t expected_length = strlen(expected);
    return strcmp(decorated, expected) == 0
        || (strncmp(decorated, expected, expected_length) == 0
            && decorated[expected_length] == '@');
}

/* ── Symbol resolution ──────────────────────────────────────────────────── *
 * Resolves COFF import symbols to function addresses:
 *   - Beacon internal functions (BeaconPrintf, BeaconDataParse, etc.)
 *   - Win32 DLL imports (KERNEL32$HeapAlloc, etc.)
 *   - Special symbols (__C_specific_handler, __ImageBase) */
void* process_symbol(char* symbolstring, char* provider, size_t provider_size) {
    void* functionaddress = NULL;
    char localcopy[1024] = { 0 };
    char* locallib = NULL;
    char* localfunc = NULL;
#if defined(_WIN32)
    int tempcounter = 0;
    HMODULE llHandle = NULL;
#endif

    strncpy(localcopy, symbolstring, sizeof(localcopy) - 1);
    if (provider != NULL && provider_size > 0) provider[0] = '\0';
    if (starts_with(symbolstring, PREPENDSYMBOLVALUE"Beacon") ||
        starts_with(symbolstring, PREPENDSYMBOLVALUE"toWideChar") ||
        starts_with(symbolstring, PREPENDSYMBOLVALUE"GetProcAddress") ||
        starts_with(symbolstring, PREPENDSYMBOLVALUE"LoadLibraryA") ||
        starts_with(symbolstring, PREPENDSYMBOLVALUE"GetModuleHandleA") ||
        starts_with(symbolstring, PREPENDSYMBOLVALUE"FreeLibrary") ||
        starts_with(symbolstring, "__C_specific_handler") ||
        starts_with(symbolstring, "__ImageBase")) {

        if (strcmp(symbolstring, "__C_specific_handler") == 0) {
            if (provider) strncpy(provider, "coffloader", provider_size - 1);
            return g_cSpecificHandler;
        }
        if (strcmp(symbolstring, "__ImageBase") == 0) {
            /* Return the BOF's first section base so REL32 relocations
             * (e.g., MSVC switch jump tables) produce valid 32-bit deltas. */
            if (provider) strncpy(provider, "coffloader", provider_size - 1);
            return g_coffImageBase ? g_coffImageBase : (void*)0;
        }

        localfunc = symbolstring + strlen(PREPENDSYMBOLVALUE);
        DEBUG_PRINT("\t\tInternalFunction: %s\n", localfunc);

#if defined(_WIN32)
        for (tempcounter = 0; tempcounter < INTERNAL_FUNCTION_COUNT; tempcounter++) {
            if (InternalFunctions[tempcounter][0] != NULL) {
                if (import_name_matches(
                        localfunc, (char*)(InternalFunctions[tempcounter][0]))) {
                    functionaddress = (void*)InternalFunctions[tempcounter][1];
                    if (provider) strncpy(provider, "coffloader", provider_size - 1);
                    return functionaddress;
                }
            }
        }
#endif
    }
    else if (strncmp(symbolstring, PREPENDSYMBOLVALUE, strlen(PREPENDSYMBOLVALUE)) == 0) {
        DEBUG_PRINT("\t\tExternal symbol\n");
        locallib = localcopy + strlen(PREPENDSYMBOLVALUE);

        locallib = strtok(locallib, "$");
        localfunc = strtok(NULL, "$");

#if defined(_WIN32)
        if (localfunc) {
            /* MODULE$Function format */
            DEBUG_PRINT("\t\tLibrary: %s\n", locallib);
            localfunc = strtok(localfunc, "@");
            DEBUG_PRINT("\t\tFunction: %s\n", localfunc);
            llHandle = LoadLibraryA(locallib);
            DEBUG_PRINT("\t\tHandle: %p\n", (void*)llHandle);
            if (llHandle != NULL) {
                functionaddress = GetProcAddress(llHandle, localfunc);
                if (functionaddress && provider)
                    strncpy(provider, locallib, provider_size - 1);
            }
            DEBUG_PRINT("\t\tProcAddress: 0x%p\n", functionaddress);
        }
        else {
            /* Bare __imp_FunctionName (no module prefix, e.g. MinGW) —
             * search common DLLs for the function */
            static const char *search_dlls[] = {
                "kernel32.dll", "ntdll.dll", "msvcrt.dll", "ucrtbase.dll",
                "ws2_32.dll", "ole32.dll", "oleaut32.dll", "advapi32.dll",
                "user32.dll", "iphlpapi.dll", "dbghelp.dll", "winhttp.dll",
                "rpcrt4.dll", "combase.dll", NULL
            };
            localfunc = strtok(locallib, "@");
            DEBUG_PRINT("\t\tBare import: %s (searching DLLs)\n", localfunc);
            for (int si = 0; search_dlls[si] && !functionaddress; si++) {
                llHandle = LoadLibraryA(search_dlls[si]);
                if (llHandle) {
                    functionaddress = GetProcAddress(llHandle, localfunc);
                    if (functionaddress) {
                        if (provider)
                            strncpy(provider, search_dlls[si], provider_size - 1);
                        DEBUG_PRINT("\t\tResolved %s from %s\n", localfunc, search_dlls[si]);
                    }
                }
            }
        }
#endif
    }
    else {
        /* Bare symbol without __imp_ prefix (e.g. malloc, free from MinGW) */
#if defined(_WIN32)
        static const char *fallback_dlls[] = {
            "msvcrt.dll", "ucrtbase.dll", "kernel32.dll", "ntdll.dll", NULL
        };
        for (int si = 0; fallback_dlls[si] && !functionaddress; si++) {
            HMODULE hm = LoadLibraryA(fallback_dlls[si]);
            if (hm) {
                functionaddress = GetProcAddress(hm, symbolstring);
                if (functionaddress) {
                    if (provider)
                        strncpy(provider, fallback_dlls[si], provider_size - 1);
                    DEBUG_PRINT("\t\tBare resolved %s from %s\n", symbolstring, fallback_dlls[si]);
                }
            }
        }
#endif
    }
    return functionaddress;
}

/* ── Symbol classification helpers ──────────────────────────────────────── */
static bool coff_symbol_is_defined(struct coff_sym *symbol) {
    return symbol->SectionNumber > 0;
}

static bool coff_symbol_is_external(struct coff_sym *symbol) {
    return symbol->StorageClass == IMAGE_SYM_CLASS_EXTERNAL
        || symbol->StorageClass == IMAGE_SYM_CLASS_EXTERNAL_DEF;
}

static bool coff_symbol_is_function(struct coff_sym *symbol) {
    return (symbol->Type & COFF_SYM_TYPE_FUNCTION) != 0;
}


/* ═══════════════════════════════════════════════════════════════════════════
 *  CoffLoad — Load and relocate a COFF file
 * ═══════════════════════════════════════════════════════════════════════════
 * Loads sections into a contiguous VirtualAlloc block, processes all
 * relocations, and resolves the named entry function.
 *
 * Does NOT call the entry — the caller invokes handle->entry() as many
 * times as needed with different argument buffers.
 *
 * On success (return 0), the caller must eventually call CoffFree().
 * On failure (return nonzero), no cleanup is needed. */
int CoffLoad(char* functionname, unsigned char* coff_data,
             uint32_t filesize, CoffHandle* handle) {
    coff_sect_t *coff_sect_ptr = NULL;
    coff_reloc_t *coff_reloc_ptr = NULL;
    int retcode = 0;
    int counter = 0;
    int reloccount = 0;
    unsigned int tempcounter = 0;
    char *symbol_name = NULL;

    COFFLOADER_RETURN_VAL_IF(handle == NULL, 1, "CoffHandle output is NULL\n");

    memset(handle, 0, sizeof(*handle));
    COFFLOADER_FAIL_IF(functionname == NULL, handle, "input",
        "INVALID_ARGUMENT", "Function name is NULL");
    COFFLOADER_FAIL_IF(coff_data == NULL, handle, "input",
        "INVALID_ARGUMENT", "COFF data is NULL");
    COFFLOADER_FAIL_IF(filesize < sizeof(struct coff_file_header), handle,
        "parse", "COFF_HEADER_TRUNCATED", "COFF header is truncated");

    struct coff_file_header *coff_header_ptr = (struct coff_file_header*)coff_data;

#if defined(_WIN64)
    COFFLOADER_FAIL_IF(coff_header_ptr->Machine != MACHINETYPE_AMD64, handle,
        "parse", "COFF_UNSUPPORTED_MACHINE", "COFF machine type is not AMD64");
#else
    COFFLOADER_FAIL_IF(coff_header_ptr->Machine != MACHINETYPE_I386, handle,
        "parse", "COFF_UNSUPPORTED_MACHINE", "COFF machine type is not I386");
#endif
    COFFLOADER_FAIL_IF(coff_header_ptr->NumberOfSections == 0, handle,
        "parse", "COFF_NO_SECTIONS", "COFF contains no sections");
    COFFLOADER_FAIL_IF(coff_header_ptr->SizeOfOptionalHeader != 0, handle,
        "parse", "COFF_OPTIONAL_HEADER_UNSUPPORTED",
        "COFF object unexpectedly contains an optional header");
    COFFLOADER_FAIL_IF(!coff_array_range_valid(
            filesize, sizeof(coff_file_header_t),
            coff_header_ptr->NumberOfSections, sizeof(coff_sect_t)), handle,
        "parse", "COFF_SECTION_TABLE_OUT_OF_BOUNDS",
        "COFF section table exceeds file size");
    COFFLOADER_FAIL_IF(coff_header_ptr->NumberOfSymbols == 0, handle,
        "parse", "COFF_NO_SYMBOLS", "COFF contains no symbols");
    COFFLOADER_FAIL_IF(coff_header_ptr->NumberOfSymbols > INT_MAX, handle,
        "parse", "COFF_SYMBOL_COUNT_UNSUPPORTED",
        "COFF symbol count exceeds loader limits");

    COFFLOADER_FAIL_IF(coff_header_ptr->PointerToSymbolTable
            < sizeof(struct coff_file_header), handle,
        "parse", "COFF_SYMBOL_TABLE_INVALID",
        "COFF symbol table offset is inside the file header");
    COFFLOADER_FAIL_IF(filesize < coff_header_ptr->PointerToSymbolTable, handle,
        "parse", "COFF_SYMBOL_TABLE_OUT_OF_BOUNDS",
        "COFF symbol table offset exceeds file size");

    /* Byte index of the string table (immediately after the symbol table) */
    COFFLOADER_FAIL_IF(!coff_array_range_valid(
            filesize, coff_header_ptr->PointerToSymbolTable,
            coff_header_ptr->NumberOfSymbols, sizeof(struct coff_sym)), handle,
        "parse", "COFF_SYMBOL_TABLE_OUT_OF_BOUNDS",
        "COFF symbol table exceeds file size");

    size_t coff_strtab_index = (size_t)coff_header_ptr->PointerToSymbolTable
        + (size_t)coff_header_ptr->NumberOfSymbols * sizeof(struct coff_sym);

    COFFLOADER_FAIL_IF(filesize < coff_strtab_index, handle, "parse",
        "COFF_SYMBOL_TABLE_OUT_OF_BOUNDS", "COFF symbol table exceeds file size");
    COFFLOADER_FAIL_IF(!coff_range_valid(filesize, coff_strtab_index,
            sizeof(uint32_t)), handle, "parse", "COFF_STRING_TABLE_TRUNCATED",
        "COFF string table size is truncated");

    uint32_t coff_strtab_size = *(uint32_t*)(coff_data + coff_strtab_index);

    COFFLOADER_FAIL_IF(coff_strtab_size < sizeof(uint32_t), handle, "parse",
        "COFF_STRING_TABLE_INVALID", "COFF string table has an invalid size");
    COFFLOADER_FAIL_IF(!coff_range_valid(filesize, coff_strtab_index,
            coff_strtab_size), handle, "parse", "COFF_STRING_TABLE_OUT_OF_BOUNDS",
        "COFF string table exceeds file size");
    COFFLOADER_FAIL_IF((size_t)filesize != coff_strtab_index + coff_strtab_size,
        handle, "parse", "COFF_TRAILING_DATA",
        "COFF file contains extraneous data");

    struct coff_sym *coff_sym_ptr =
        (struct coff_sym*)(coff_data + coff_header_ptr->PointerToSymbolTable);
    char *coff_strtab = (char*)(coff_data + coff_strtab_index);

    COFFLOADER_FAIL_IF(coff_header_ptr->PointerToSymbolTable
            < sizeof(coff_file_header_t)
              + (size_t)coff_header_ptr->NumberOfSections * sizeof(coff_sect_t),
        handle, "parse", "COFF_SYMBOL_TABLE_OVERLAP",
        "COFF symbol table overlaps the section table");

    /* Validate every file-backed section and relocation table before loading. */
    for (counter = 0; counter < coff_header_ptr->NumberOfSections; counter++) {
        coff_sect_t *section = (coff_sect_t*)(coff_data
            + sizeof(coff_file_header_t) + sizeof(coff_sect_t) * counter);

        if (section->PointerToRawData != 0
            && !coff_range_valid(filesize, section->PointerToRawData,
                                 section->SizeOfRawData)) {
            DEBUG_PRINT("Section %d raw data exceeds file size\n", counter);
            return coff_fail(handle, "parse", "COFF_SECTION_DATA_OUT_OF_BOUNDS",
                             "Section raw data exceeds file size");
        }
        if (section->NumberOfRelocations != 0
            && !coff_array_range_valid(filesize, section->PointerToRelocations,
                                       section->NumberOfRelocations,
                                       sizeof(coff_reloc_t))) {
            DEBUG_PRINT("Section %d relocation table exceeds file size\n", counter);
            return coff_fail(handle, "parse", "COFF_RELOCATION_TABLE_OUT_OF_BOUNDS",
                             "Section relocation table exceeds file size");
        }
    }

    /* Validate primary symbol records and their auxiliary entry spans. */
    for (tempcounter = 0; tempcounter < coff_header_ptr->NumberOfSymbols; ) {
        coff_sym_t *symbol = &coff_sym_ptr[tempcounter];
        char validated_short_name[9];
        if (symbol->NumberOfAuxSymbols
            > coff_header_ptr->NumberOfSymbols - tempcounter - 1) {
            DEBUG_PRINT("Symbol %u auxiliary records exceed symbol table\n",
                        tempcounter);
            return coff_fail(handle, "parse", "COFF_AUX_SYMBOL_OUT_OF_BOUNDS",
                             "Auxiliary symbol records exceed the symbol table");
        }
        if (symbol->SectionNumber > coff_header_ptr->NumberOfSections) {
            DEBUG_PRINT("Symbol %u references invalid section %d\n",
                        tempcounter, symbol->SectionNumber);
            return coff_fail(handle, "parse", "COFF_BAD_SECTION_INDEX",
                             "Symbol references an invalid section");
        }
        if (coff_get_symbol_name(symbol, coff_strtab, coff_strtab_size,
                                 validated_short_name) == NULL) {
            DEBUG_PRINT("Symbol %u has an invalid name\n", tempcounter);
            return coff_fail(handle, "parse", "COFF_BAD_SYMBOL_NAME",
                             "Symbol has an invalid name");
        }
        tempcounter += 1 + symbol->NumberOfAuxSymbols;
    }

#ifdef _WIN32
    void* funcptrlocation = NULL;
    size_t offsetvalue = 0;
#endif
    char* contiguousBase = NULL;
    size_t gotOffset = 0;
    size_t allocationSize = 0;
    char* entryfuncname = functionname;
#if defined(__x86_64__) || defined(_WIN64)
#ifdef _WIN32
    uint64_t longoffsetvalue = 0;
#endif
#else
    /* 32-bit: prepend underscore to match COFF symbol naming */
    entryfuncname = calloc(strlen(functionname) + 2, 1);
    if (entryfuncname == NULL) {
        return 1;
    }
    (void)sprintf(entryfuncname, "_%s", functionname);
#endif

    HMODULE kern = GetModuleHandleA("kernel32.dll");
    if (kern == NULL) {
        return coff_fail(handle, "resolve", "COFF_RUNTIME_RESOLUTION_FAILED",
                         "Failed to locate kernel32.dll");
    }
    g_cSpecificHandler = (void*)GetProcAddress(kern, "__C_specific_handler");
    if (g_cSpecificHandler == NULL) {
        return coff_fail(handle, "resolve", "COFF_RUNTIME_RESOLUTION_FAILED",
                         "Failed to resolve __C_specific_handler");
    }
    DEBUG_PRINT("found __C_specific_handler at %p\n", g_cSpecificHandler);

#ifdef _WIN32
    char** sectionMapping = NULL;
#ifdef DEBUG
    int *sectionSize = NULL;
#endif
    coff_entry_fn foo = NULL;
    void **functionMapping = NULL;
    size_t functionMappingCount = 0;
    size_t relocationCount = 0;
#endif
    char symbol_shortname_buffer[9] = {0};

    DEBUG_PRINT("Machine 0x%X\n", coff_header_ptr->Machine);
    DEBUG_PRINT("Number of sections: %d\n", coff_header_ptr->NumberOfSections);
    DEBUG_PRINT("TimeDateStamp : %X\n", coff_header_ptr->TimeDateStamp);
    DEBUG_PRINT("PointerToSymbolTable : 0x%X\n", coff_header_ptr->PointerToSymbolTable);
    DEBUG_PRINT("NumberOfSymbols: %u\n", coff_header_ptr->NumberOfSymbols);
    DEBUG_PRINT("OptionalHeaderSize: %d\n", coff_header_ptr->SizeOfOptionalHeader);
    DEBUG_PRINT("Characteristics: %d\n", coff_header_ptr->Characteristics);
    DEBUG_PRINT("\n");

    sectionMapping = (char**)calloc(sizeof(char*) * (coff_header_ptr->NumberOfSections + 1), 1);
#ifdef DEBUG
    sectionSize = (int*)calloc(sizeof(int) * (coff_header_ptr->NumberOfSections + 1), 1);
#endif
    if (sectionMapping == NULL) {
        DEBUG_PRINT("Failed to allocate sectionMapping\n");
        goto cleanup;
    }

    /* ── Contiguous allocation for all sections + GOT ────────────────────
     * All sections are placed in a single VirtualAlloc block, page-aligned.
     * The GOT (function pointer table for imports) is appended at the end.
     * This ensures all REL32 cross-section relocations stay within the
     * 32-bit displacement range on x64. */
    {
        size_t totalSize = 0;
        for (counter = 0; counter < coff_header_ptr->NumberOfSections; counter++) {
            coff_sect_ptr = (coff_sect_t*)(coff_data + sizeof(coff_file_header_t)
                                           + (sizeof(coff_sect_t) * counter));
            size_t aligned = ((size_t)coff_sect_ptr->SizeOfRawData + 0xFFF) & ~(size_t)0xFFF;
            if (aligned == 0) aligned = 0x1000; /* minimum 1 page */
            totalSize += aligned;
            relocationCount += coff_sect_ptr->NumberOfRelocations;
        }

        gotOffset = totalSize;
        /* 16 bytes per slot: bare symbols need 14-byte trampolines (2 slots) */
        size_t gotSize = (((size_t)relocationCount * 16) + 0xFFF) & ~(size_t)0xFFF;
        totalSize += gotSize;
        allocationSize = totalSize;

        contiguousBase = (char*)VirtualAlloc(NULL, totalSize,
                                             MEM_COMMIT | MEM_RESERVE,
                                             PAGE_READWRITE);
        if (contiguousBase == NULL) {
            DEBUG_PRINT("Failed to allocate contiguous block of 0x%zx bytes\n", totalSize);
            coff_fail(handle, "load", "COFF_ALLOCATION_FAILED",
                      "Failed to allocate the COFF image");
            retcode = 1;
            goto cleanup;
        }
        DEBUG_PRINT("Allocated contiguous block at %p (0x%zx bytes)\n",
                    contiguousBase, totalSize);
        g_coffImageBase = contiguousBase;

        size_t offset = 0;
        for (counter = 0; counter < coff_header_ptr->NumberOfSections; counter++) {
            coff_sect_ptr = (coff_sect_t*)(coff_data + sizeof(coff_file_header_t)
                                           + (sizeof(coff_sect_t) * counter));
            size_t aligned = ((size_t)coff_sect_ptr->SizeOfRawData + 0xFFF) & ~(size_t)0xFFF;
            if (aligned == 0) aligned = 0x1000;

            sectionMapping[counter] = contiguousBase + offset;
#ifdef DEBUG
            sectionSize[counter] = coff_sect_ptr->SizeOfRawData;
#endif
            DEBUG_PRINT("Section %d (%.8s) at %p (0x%x bytes)\n",
                        counter, coff_sect_ptr->Name,
                        sectionMapping[counter], coff_sect_ptr->SizeOfRawData);
            if (coff_sect_ptr->PointerToRawData != 0) {
                memcpy(sectionMapping[counter],
                       coff_data + coff_sect_ptr->PointerToRawData,
                       coff_sect_ptr->SizeOfRawData);
            }
            offset += aligned;
        }
    }
    DEBUG_PRINT("Total Relocations: %zu\n", relocationCount);
    handle->relocationCount = relocationCount;

#ifdef _WIN32
    functionMapping = (void**)(contiguousBase + gotOffset);
    DEBUG_PRINT("functionMapping (GOT) at %p (offset 0x%zx)\n",
                functionMapping, gotOffset);
#endif

    handle->imageSize = allocationSize;
    if (build_section_info(handle, coff_data, coff_header_ptr, sectionMapping,
                           coff_strtab, coff_strtab_size) != 0) {
        retcode = 1;
        goto cleanup;
    }

    /* ── Process relocations ─────────────────────────────────────────────── */
    for (counter = 0; counter < coff_header_ptr->NumberOfSections; counter++) {
        DEBUG_PRINT("Doing Relocations of section: %d\n", counter);
        coff_sect_ptr = (coff_sect_t*)(coff_data + sizeof(coff_file_header_t)
                                       + (sizeof(coff_sect_t) * counter));
        coff_reloc_ptr = (coff_reloc_t*)(coff_data + coff_sect_ptr->PointerToRelocations);

        for (reloccount = 0; reloccount < coff_sect_ptr->NumberOfRelocations; reloccount++) {
            size_t relocation_width =
                coff_reloc_ptr->Type == IMAGE_REL_AMD64_ADDR64 ? 8 : 4;
            coff_sym_t *reloc_symbol;

            if (coff_reloc_ptr->SymbolTableIndex >= coff_header_ptr->NumberOfSymbols) {
                DEBUG_PRINT("Relocation symbol index exceeds symbol table\n");
                coff_fail(handle, "relocate", "COFF_BAD_SYMBOL_INDEX",
                          "Relocation symbol index exceeds the symbol table");
                retcode = 1;
                goto cleanup;
            }
            if (coff_reloc_ptr->VirtualAddress > coff_sect_ptr->SizeOfRawData
                || relocation_width > coff_sect_ptr->SizeOfRawData
                                      - coff_reloc_ptr->VirtualAddress) {
                DEBUG_PRINT("Relocation write exceeds section %d\n", counter);
                coff_fail(handle, "relocate", "COFF_RELOCATION_OUT_OF_BOUNDS",
                          "Relocation write exceeds its target section");
                retcode = 1;
                goto cleanup;
            }
            reloc_symbol = &coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex];
            if (reloc_symbol->SectionNumber > coff_header_ptr->NumberOfSections) {
                DEBUG_PRINT("Relocation references invalid section %d\n",
                            reloc_symbol->SectionNumber);
                coff_fail(handle, "relocate", "COFF_BAD_SECTION_INDEX",
                          "Relocation symbol references an invalid section");
                retcode = 1;
                goto cleanup;
            }
            DEBUG_PRINT("\tVirtualAddress: 0x%X\n", coff_reloc_ptr->VirtualAddress);
            DEBUG_PRINT("\tSymbolTableIndex: 0x%X\n", coff_reloc_ptr->SymbolTableIndex);
            DEBUG_PRINT("\tType: 0x%X\n", coff_reloc_ptr->Type);

            /* Resolve symbol name — long names come from the string table */
            symbol_name = (char*)coff_get_symbol_name(
                reloc_symbol, coff_strtab, coff_strtab_size,
                symbol_shortname_buffer);
            if (symbol_name == NULL) {
                DEBUG_PRINT("Relocation references an invalid symbol name\n");
                coff_fail(handle, "parse", "COFF_BAD_SYMBOL_NAME",
                          "Relocation references an invalid symbol name");
                retcode = 1;
                goto cleanup;
            }

            DEBUG_PRINT("\tSymName: %s\n", symbol_name);
            DEBUG_PRINT("\tSectionNumber: 0x%X\n",
                        coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber);

            /* Resolve the symbol to an address */
            if (coff_symbol_is_defined(&coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex])) {
                /* Locally defined symbol */
                funcptrlocation = sectionMapping[
                    coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1];
                funcptrlocation = (void*)((char*)funcptrlocation
                    + coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value);
            }
            else if (coff_symbol_is_external(&coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex])
                     && coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value == 0) {
                char provider[64] = {0};
                const char *dispatch;
                void *resolved_import;
                int import_resolved;
                /* Imported symbol — resolve and map into GOT */
                funcptrlocation = process_symbol(symbol_name, provider,
                                                 sizeof(provider));
                resolved_import = funcptrlocation;
                import_resolved = funcptrlocation != NULL;
                if (strncmp(symbol_name, "__imp_", 6) == 0) {
                    dispatch = "pointer_slot";
                } else if (coff_symbol_is_function(
                               &coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex])) {
                    dispatch = "trampoline";
                } else {
                    dispatch = "direct";
                }
                record_import(handle, symbol_name, provider, dispatch,
                              resolved_import, import_resolved);
                if (funcptrlocation == NULL) {
                    /* Record the unresolved import but continue checking
                     * all other imports so the caller gets a complete list. */
                    if (handle->unresolvedCount < 256) {
                        if (!handle->unresolvedImports) {
                            handle->unresolvedImports = (CoffUnresolvedImport*)calloc(
                                256, sizeof(CoffUnresolvedImport));
                        }
                        if (handle->unresolvedImports) {
                            CoffUnresolvedImport *ui = &handle->unresolvedImports[handle->unresolvedCount];
                            strncpy(ui->symbol, symbol_name, sizeof(ui->symbol) - 1);
                            /* Parse MODULE$Function from __imp_MODULE$Function */
                            {
                                char tmp[256] = {0};
                                strncpy(tmp, symbol_name, sizeof(tmp) - 1);
                                char *lib = tmp;
                                if (strncmp(lib, PREPENDSYMBOLVALUE, strlen(PREPENDSYMBOLVALUE)) == 0)
                                    lib += strlen(PREPENDSYMBOLVALUE);
                                char *dollar = strchr(lib, '$');
                                if (dollar) {
                                    *dollar = '\0';
                                    strncpy(ui->library, lib, sizeof(ui->library) - 1);
                                    char *func = dollar + 1;
                                    char *at = strchr(func, '@');
                                    if (at) *at = '\0';
                                    strncpy(ui->function, func, sizeof(ui->function) - 1);
                                } else {
                                    strncpy(ui->library, lib, sizeof(ui->library) - 1);
                                }
                            }
                            diagnose_unresolved(symbol_name, ui);
                            handle->unresolvedCount++;
                        }
                    }
                    /* Use a dummy address so relocation proceeds.
                     * The import won't work, but we can check ALL symbols. */
                    static char _dummyImportTarget = 0;
                    funcptrlocation = &_dummyImportTarget;
                }
                if (strncmp(symbol_name, "__imp_", 6) == 0) {
                    /* __imp_ symbol: indirect call/jmp (FF 15 / FF 25)
                     * loads function pointer FROM GOT → plain GOT entry */
                    functionMapping[functionMappingCount] = funcptrlocation;
                    funcptrlocation = &functionMapping[functionMappingCount];
                    functionMappingCount += 1;
                    handle->pointerSlotCount++;
                } else if (coff_symbol_is_function(
                               &coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex])) {
                    /* Bare symbol: direct call/jmp (E8 / E9)
                     * jumps TO the address → needs executable trampoline
                     * Trampoline: FF 25 00 00 00 00 [8-byte addr] = jmp [rip+0]; .quad addr */
                    char *thunk = (char*)&functionMapping[functionMappingCount];
                    thunk[0] = 0xFF; thunk[1] = 0x25;
                    thunk[2] = thunk[3] = thunk[4] = thunk[5] = 0x00;
                    memcpy(thunk + 6, &funcptrlocation, sizeof(void*));
                    funcptrlocation = thunk;
                    functionMappingCount += 2; /* 14 bytes, 2 slots (16 bytes) */
                    handle->trampolineCount++;
                } else {
                    /* Bare data symbol.  Relocations must reference the export
                     * itself; treating data as an executable thunk silently
                     * returns the thunk opcodes as the data value. */
                    DEBUG_PRINT("\t\tBare data symbol %s at %p\n",
                                symbol_name, funcptrlocation);
                    handle->directImportCount++;
                }
            }
            else {
                /* Non-import undefined symbol — COMDAT artifact, RTTI, etc. */
                DEBUG_PRINT("Relocation %d in section %d references undefined symbol %s\n",
                            reloccount, counter, symbol_name);
                if (handle->unresolvedCount < 256) {
                    if (!handle->unresolvedImports) {
                        handle->unresolvedImports = (CoffUnresolvedImport*)calloc(
                            256, sizeof(CoffUnresolvedImport));
                    }
                    if (handle->unresolvedImports) {
                        CoffUnresolvedImport *ui = &handle->unresolvedImports[handle->unresolvedCount];
                        strncpy(ui->symbol, symbol_name, sizeof(ui->symbol) - 1);
                        diagnose_unresolved(symbol_name, ui);
                        handle->unresolvedCount++;
                    }
                }
                /* Dummy target so we can continue checking remaining symbols */
                static char _dummyComdat = 0;
                funcptrlocation = &_dummyComdat;
            }

            /* ── Apply relocation by type ────────────────────────────────── */
#ifdef _WIN32
#ifdef _WIN64
            if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_ADDR64) {
                memcpy(&longoffsetvalue,
                       sectionMapping[counter] + coff_reloc_ptr->VirtualAddress,
                       sizeof(uint64_t));
                DEBUG_PRINT("\tReadin longOffsetValue : 0x%llX\n", longoffsetvalue);
                longoffsetvalue += (uint64_t)funcptrlocation;
                DEBUG_PRINT("\tModified longOffsetValue : 0x%llX\n", longoffsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress,
                       &longoffsetvalue, sizeof(uint64_t));
            }
            else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_ADDR32NB) {
                uint32_t addend = 0;
                uint64_t rva;
                memcpy(&addend,
                       sectionMapping[counter] + coff_reloc_ptr->VirtualAddress,
                       sizeof(addend));
                if ((uintptr_t)funcptrlocation < (uintptr_t)contiguousBase) {
                    DEBUG_PRINT("ADDR32NB target is outside the COFF image\n");
                    retcode = 1;
                    goto cleanup;
                }
                rva = (uint64_t)((uintptr_t)funcptrlocation - (uintptr_t)contiguousBase)
                      + addend;
                if (rva > UINT32_MAX) {
                    DEBUG_PRINT("ADDR32NB target exceeds 32-bit RVA range\n");
                    retcode = 1;
                    goto cleanup;
                }
                offsetvalue = (uint32_t)rva;
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress,
                       &offsetvalue, sizeof(uint32_t));
            }
            else if (coff_reloc_ptr->Type >= IMAGE_REL_AMD64_REL32
                     && coff_reloc_ptr->Type <= IMAGE_REL_AMD64_REL32_5) {
                int extra = coff_reloc_ptr->Type - IMAGE_REL_AMD64_REL32;
                int32_t addend = 0;
                int64_t relocated;
                char *site = sectionMapping[counter] + coff_reloc_ptr->VirtualAddress;
                memcpy(&addend, site, sizeof(addend));
                relocated = (int64_t)addend
                            + (int64_t)(intptr_t)funcptrlocation
                            - (int64_t)(intptr_t)(site + 4 + extra);
                if (relocated < INT32_MIN || relocated > INT32_MAX) {
                    DEBUG_PRINT("REL32 target is outside signed 32-bit range\n");
                    coff_fail(handle, "relocate", "COFF_REL32_OUT_OF_RANGE",
                              "REL32 target is outside the signed 32-bit range");
                    retcode = 1;
                    goto cleanup;
                }
                addend = (int32_t)relocated;
                memcpy(site, &addend, sizeof(addend));
            }
            else if (coff_reloc_ptr->Type != IMAGE_REL_AMD64_ABSOLUTE) {
                DEBUG_PRINT("No handler for relocation type: %d\n", coff_reloc_ptr->Type);
                coff_fail(handle, "relocate", "COFF_UNSUPPORTED_RELOCATION",
                          "COFF contains an unsupported relocation type");
                retcode = 1;
                goto cleanup;
            }
#else
            /* ── i386 relocations ──────────────────────────────────────── */
            if (coff_reloc_ptr->Type == IMAGE_REL_I386_DIR32) {
                offsetvalue = 0;
                memcpy(&offsetvalue,
                       sectionMapping[counter] + coff_reloc_ptr->VirtualAddress,
                       sizeof(int32_t));
                offsetvalue = (uint32_t)funcptrlocation + offsetvalue;
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress,
                       &offsetvalue, sizeof(uint32_t));
            }
            else if (coff_reloc_ptr->Type == IMAGE_REL_I386_REL32) {
                offsetvalue = 0;
                memcpy(&offsetvalue,
                       sectionMapping[counter] + coff_reloc_ptr->VirtualAddress,
                       sizeof(int32_t));
                offsetvalue += (uint32_t)funcptrlocation
                               - (uint32_t)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress,
                       &offsetvalue, sizeof(uint32_t));
            }
#endif /* _WIN64 */
#endif /* _WIN32 */

            DEBUG_PRINT("\tValueNumber: 0x%X\n",
                        coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value);
            DEBUG_PRINT("\tSectionNumber: 0x%X\n",
                        coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber);
            coff_reloc_ptr += 1;
            DEBUG_PRINT("\n");
        }
        DEBUG_PRINT("\n");
    }

    /* ── Check for unresolved imports ──────────────────────────────────── */
    if (handle->unresolvedCount > 0) {
        coff_fail(handle, "resolve", "COFF_UNRESOLVED_IMPORTS",
                  "One or more imports could not be resolved");
        retcode = 1;
        goto cleanup;
    }

#if defined(_WIN32) && defined(_WIN64)
    /* MSVC emits image-relative RUNTIME_FUNCTION records in .pdata.  The
     * ADDR32NB relocation path above has made those records valid for our
     * contiguous image; register them before any BOF code can execute. */
    if (register_unwind_tables(handle, sectionMapping, contiguousBase,
                               allocationSize) != 0) {
        retcode = 1;
        goto cleanup;
    }
#endif

    /* Finalize page protections only after every relocation and thunk write.
     * Sections are page-aligned, so their protections do not bleed together. */
    for (counter = 0; counter < coff_header_ptr->NumberOfSections; counter++) {
        DWORD old_protect = 0;
        DWORD new_protect;
        size_t mapped_size;

        coff_sect_ptr = (coff_sect_t*)(coff_data + sizeof(coff_file_header_t)
                                       + sizeof(coff_sect_t) * counter);
        mapped_size = ((size_t)coff_sect_ptr->SizeOfRawData + 0xFFF)
                      & ~(size_t)0xFFF;
        if (mapped_size == 0) mapped_size = 0x1000;

        if (coff_sect_ptr->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            new_protect = PAGE_EXECUTE_READ;
        } else if (coff_sect_ptr->Characteristics & IMAGE_SCN_MEM_WRITE) {
            new_protect = PAGE_READWRITE;
        } else {
            new_protect = PAGE_READONLY;
        }

        if (!VirtualProtect(sectionMapping[counter], mapped_size,
                            new_protect, &old_protect)) {
            DEBUG_PRINT("VirtualProtect failed for section %d: %lu\n",
                        counter, GetLastError());
            coff_fail(handle, "protect", "COFF_PROTECTION_FAILED",
                      "Failed to apply final section protection");
            retcode = 1;
            goto cleanup;
        }
    }

    if (allocationSize > gotOffset) {
        DWORD old_protect = 0;
        if (!VirtualProtect(contiguousBase + gotOffset,
                            allocationSize - gotOffset,
                            PAGE_EXECUTE_READ, &old_protect)) {
            DEBUG_PRINT("VirtualProtect failed for import thunks: %lu\n",
                        GetLastError());
            coff_fail(handle, "protect", "COFF_PROTECTION_FAILED",
                      "Failed to protect the import thunk region");
            retcode = 1;
            goto cleanup;
        }
    }
    if (!FlushInstructionCache(GetCurrentProcess(), contiguousBase,
                               allocationSize)) {
        DEBUG_PRINT("FlushInstructionCache failed: %lu\n", GetLastError());
        coff_fail(handle, "protect", "COFF_ICACHE_FLUSH_FAILED",
                  "Failed to flush the instruction cache");
        retcode = 1;
        goto cleanup;
    }

    /* Debug: dump section bytes */
#if DEBUG
#ifdef _WIN32
    for (tempcounter = 0; tempcounter < coff_header_ptr->NumberOfSections; tempcounter++) {
        DEBUG_PRINT("Section: %u\n", tempcounter);
        if (sectionMapping[tempcounter] != NULL) {
            DEBUG_PRINT("\t");
            for (counter = 0; counter < sectionSize[tempcounter]; counter++) {
                DEBUG_PRINT("%02X ", (uint8_t)(sectionMapping[tempcounter][counter]));
            }
            DEBUG_PRINT("\n");
        }
    }
#endif
#endif

    /* ── Find entry function in symbol table ─────────────────────────────── */
    {
        DEBUG_PRINT("Searching %d symbols for '%s'\n",
                    coff_header_ptr->NumberOfSymbols, entryfuncname);
        for (tempcounter = 0; tempcounter < coff_header_ptr->NumberOfSymbols; tempcounter++) {
            const char* symname;
            char symnamebuf[9];
            symname = coff_get_symbol_name(&coff_sym_ptr[tempcounter],
                                           coff_strtab, coff_strtab_size,
                                           symnamebuf);

            if (symname != NULL && strcmp(symname, entryfuncname) == 0
                && coff_sym_ptr[tempcounter].SectionNumber > 0
                && coff_sym_ptr[tempcounter].SectionNumber
                   <= coff_header_ptr->NumberOfSections) {
                coff_sect_t *entry_section = (coff_sect_t*)(coff_data
                    + sizeof(coff_file_header_t)
                    + sizeof(coff_sect_t)
                      * (coff_sym_ptr[tempcounter].SectionNumber - 1));
                if (coff_sym_ptr[tempcounter].Value > entry_section->SizeOfRawData) {
                    DEBUG_PRINT("Entry symbol lies outside its section\n");
                    retcode = 1;
                    goto cleanup;
                }
                DEBUG_PRINT("\t\tFound entry!\n");
#ifdef _WIN32
                foo = (coff_entry_fn)(
                    sectionMapping[coff_sym_ptr[tempcounter].SectionNumber - 1]
                    + coff_sym_ptr[tempcounter].Value);
                DEBUG_PRINT("Entry '%s' at %p (sec=%d val=0x%x)\n",
                            entryfuncname, foo,
                            coff_sym_ptr[tempcounter].SectionNumber,
                            coff_sym_ptr[tempcounter].Value);
#endif
            }
            /* Skip auxiliary symbol entries */
            tempcounter += coff_sym_ptr[tempcounter].NumberOfAuxSymbols;
        }
    }

    /* ── Success path: entry found ───────────────────────────────────────── */
    if (foo != NULL) {
        handle->imageBase = contiguousBase;
        handle->entry = foo;

        /* ── Build section info table for crash resolution ── */
        /* ── Build symbol table for crash resolution ── */
        {
            /* Count defined symbols first */
            int defCount = 0;
            unsigned int si;
            for (si = 0; si < coff_header_ptr->NumberOfSymbols; ) {
                const coff_sym_t* symbol = &coff_sym_ptr[si];
                if (symbol->SectionNumber > 0)
                    defCount++;
                si += 1u + symbol->NumberOfAuxSymbols;
            }

            handle->symbols = (CoffSymEntry*)calloc(defCount, sizeof(CoffSymEntry));
            handle->symbolCount = 0;
            if (handle->symbols) {
                for (si = 0; si < coff_header_ptr->NumberOfSymbols; ) {
                    const coff_sym_t* symbol = &coff_sym_ptr[si];
                    if (symbol->SectionNumber > 0
                        && symbol->SectionNumber <= coff_header_ptr->NumberOfSections) {
                        CoffSymEntry *e = &handle->symbols[handle->symbolCount];
                        char short_name[9];
                        const char* metadata_name;

                        /* Compute absolute address */
                        e->addr = (uintptr_t)sectionMapping[symbol->SectionNumber - 1]
                                  + symbol->Value;
                        e->section = symbol->SectionNumber;

                        /* Resolve name */
                        metadata_name = coff_get_symbol_name(
                            symbol, coff_strtab, coff_strtab_size, short_name);
                        if (metadata_name != NULL)
                            strncpy(e->name, metadata_name, sizeof(e->name) - 1);
                        e->name[sizeof(e->name) - 1] = '\0';

                        handle->symbolCount++;
                    }
                    si += 1u + symbol->NumberOfAuxSymbols;
                }

                /* Sort symbols by address for binary search. */
                qsort(handle->symbols, (size_t)defCount,
                      sizeof(CoffSymEntry), compare_symbol_addresses);
            }
        }

        if (sectionMapping) free(sectionMapping);
#ifdef DEBUG
        if (sectionSize) free(sectionSize);
#endif
        if (entryfuncname && entryfuncname != functionname) free(entryfuncname);
        return 0;
    }

    /* Entry function not found */
    DEBUG_PRINT("Entry function '%s' not found in COFF symbol table\n", entryfuncname);
    coff_fail(handle, "resolve", "COFF_ENTRY_NOT_FOUND",
              "Requested entry function was not found");
    retcode = 1;

    /* ── Error cleanup: free everything including code pages ──────────────── */
#ifdef _WIN32
    cleanup:
#if defined(_WIN64)
        unregister_unwind_tables(handle);
#endif
        if (sectionMapping) {
            if (contiguousBase) {
                VirtualFree(contiguousBase, 0, MEM_RELEASE);
                g_coffImageBase = NULL;
            }
            free(sectionMapping);
            sectionMapping = NULL;
        }
#ifdef DEBUG
        if (sectionSize) {
            free(sectionSize);
            sectionSize = NULL;
        }
#endif
#endif
        if (entryfuncname && entryfuncname != functionname) {
            free(entryfuncname);
        }
        DEBUG_PRINT("CoffLoad returning %d\n", retcode);
        return retcode;
}


/* ═══════════════════════════════════════════════════════════════════════════
 *  CoffFree — Release a loaded COFF's code pages
 * ═══════════════════════════════════════════════════════════════════════════ */
void CoffFree(CoffHandle* handle) {
    if (!handle) return;
#if defined(_WIN32) && defined(_WIN64)
    unregister_unwind_tables(handle);
#endif
    if (handle->imageBase) {
        VirtualFree(handle->imageBase, 0, MEM_RELEASE);
        handle->imageBase = NULL;
        g_coffImageBase = NULL;
    }
    if (handle->symbols) { free(handle->symbols); handle->symbols = NULL; }
    if (handle->sections) { free(handle->sections); handle->sections = NULL; }
    if (handle->imports) { free(handle->imports); handle->imports = NULL; }
    if (handle->unresolvedImports) { free(handle->unresolvedImports); handle->unresolvedImports = NULL; }
    handle->symbolCount = 0;
    handle->sectionCount = 0;
    handle->unresolvedCount = 0;
    handle->importCount = 0;
    handle->pdataSectionCount = 0;
    handle->entry = NULL;
}


/* ═══════════════════════════════════════════════════════════════════════════
 *  CoffResolveAddress — Map a crash address to nearest symbol + section
 * ═══════════════════════════════════════════════════════════════════════════ */
int CoffResolveAddress(CoffHandle* handle, uintptr_t addr, CoffCrashInfo* info) {
    if (!handle || !info) return 0;
    memset(info, 0, sizeof(*info));

    uintptr_t base = (uintptr_t)handle->imageBase;
    uintptr_t end  = base + handle->imageSize;

    /* Check if address falls within the COFF image */
    if (addr < base || addr >= end) return 0;

    info->resolved = 1;

    /* Find which section contains the address */
    for (int i = 0; i < handle->sectionCount; i++) {
        uintptr_t secStart = handle->sections[i].start;
        uintptr_t secEnd   = secStart + handle->sections[i].size;
        if (addr >= secStart && addr < secEnd) {
            strncpy(info->sectionName, handle->sections[i].name,
                    sizeof(info->sectionName) - 1);
            info->sectionName[sizeof(info->sectionName) - 1] = '\0';
            info->sectionIndex = i;
            info->sectionOffset = (int)(addr - secStart);
            break;
        }
    }

    /* Binary search for the nearest symbol at or before the address */
    if (handle->symbolCount > 0 && handle->symbols) {
        int lo = 0, hi = handle->symbolCount - 1;
        int best = -1;
        while (lo <= hi) {
            int mid = (lo + hi) / 2;
            if (handle->symbols[mid].addr <= addr) {
                best = mid;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        if (best >= 0) {
            strncpy(info->symbolName, handle->symbols[best].name, sizeof(info->symbolName) - 1);
            info->symbolName[sizeof(info->symbolName) - 1] = '\0';
            info->symbolOffset = (int)(addr - handle->symbols[best].addr);
        }
    }

    return 1;
}
