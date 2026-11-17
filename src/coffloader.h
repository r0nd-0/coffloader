/*
 * coffloader.h — General-Purpose COFF/BOF Loader
 * -----------------------------------------------
 * Structures and API for loading, relocating, and executing
 * Cobalt Strike Beacon Object Files (BOFs) outside of Beacon.
 *
 * Features:
 *   - Contiguous section allocation (REL32 safe across 64-bit address space)
 *   - __ImageBase resolution for MSVC jump tables
 *   - String-table-aware symbol lookup (long symbol names)
 *   - Auxiliary symbol entry skipping
 *   - Multi-command mode (CoffLoad/CoffFree — call entry repeatedly)
 */
#ifndef COFFLOADER_H_
#define COFFLOADER_H_

#include <stdio.h>
#include <stdint.h>

#define COFFLOADER_VERSION "0.2.0"
#define COFFLOADER_JSON_SCHEMA_ID "coffloader/v2"
#define COFFLOADER_JSON_SCHEMA_VERSION 2

/* ── COFF File Header (sizeof 20) ───────────────────────────────────────── */
typedef struct coff_file_header {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} coff_file_header_t;

#define MACHINETYPE_AMD64 0x8664
#define MACHINETYPE_I386  0x014C

#pragma pack(push, 1)

/* ── COFF Section Header (sizeof 40) ────────────────────────────────────── */
typedef struct coff_sect {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLineNumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} coff_sect_t;

/* ── COFF Relocation Entry ──────────────────────────────────────────────── */
typedef struct coff_reloc {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
} coff_reloc_t;

/* ── COFF Symbol Table Entry ────────────────────────────────────────────── */
typedef struct coff_sym {
    union {
        char     Name[8];       /* Inline name (<=8 chars, may lack NUL) */
        uint32_t value[2];      /* value[0]==0 → value[1] is strtab offset */
    } first;
    uint32_t Value;
    int16_t  SectionNumber;
    uint16_t Type;
    uint8_t  StorageClass;
    uint8_t  NumberOfAuxSymbols;
} coff_sym_t;

#pragma pack(pop)

/* ── AMD64 Relocation Types ─────────────────────────────────────────────── */
#define IMAGE_REL_AMD64_ABSOLUTE    0x0000
#define IMAGE_REL_AMD64_ADDR64      0x0001
#define IMAGE_REL_AMD64_ADDR32      0x0002
#define IMAGE_REL_AMD64_ADDR32NB    0x0003
#define IMAGE_REL_AMD64_REL32       0x0004
#define IMAGE_REL_AMD64_REL32_1     0x0005
#define IMAGE_REL_AMD64_REL32_2     0x0006
#define IMAGE_REL_AMD64_REL32_3     0x0007
#define IMAGE_REL_AMD64_REL32_4     0x0008
#define IMAGE_REL_AMD64_REL32_5     0x0009
#define IMAGE_REL_AMD64_SECTION     0x000A
#define IMAGE_REL_AMD64_SECREL      0x000B
#define IMAGE_REL_AMD64_SECREL7     0x000C
#define IMAGE_REL_AMD64_TOKEN       0x000D
#define IMAGE_REL_AMD64_SREL32      0x000E
#define IMAGE_REL_AMD64_PAIR        0x000F
#define IMAGE_REL_AMD64_SSPAN32     0x0010

/* Derived symbol type used by both MSVC and MinGW for functions. */
#define COFF_SYM_TYPE_FUNCTION      0x0020

/* ── I386 Relocation Types ──────────────────────────────────────────────── */
#define IMAGE_REL_I386_ABSOLUTE     0x0000
#define IMAGE_REL_I386_DIR16        0x0001
#define IMAGE_REL_I386_REL16        0x0002
#define IMAGE_REL_I386_DIR32        0x0006
#define IMAGE_REL_I386_DIR32NB      0x0007
#define IMAGE_REL_I386_SEG12        0x0009
#define IMAGE_REL_I386_SECTION      0x000A
#define IMAGE_REL_I386_SECREL       0x000B
#define IMAGE_REL_I386_TOKEN        0x000C
#define IMAGE_REL_I386_SECREL7      0x000D
#define IMAGE_REL_I386_REL32        0x0014

/* ── Section Characteristic Flags ───────────────────────────────────────── */
#define IMAGE_SCN_MEM_WRITE              0x80000000
#define IMAGE_SCN_MEM_READ               0x40000000
#define IMAGE_SCN_MEM_EXECUTE            0x20000000
#define IMAGE_SCN_ALIGN_16BYTES          0x00500000
#define IMAGE_SCN_MEM_NOT_CACHED         0x04000000
#define IMAGE_SCN_MEM_NOT_PAGED          0x08000000
#define IMAGE_SCN_MEM_SHARED             0x10000000
#define IMAGE_SCN_CNT_CODE               0x00000020
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_MEM_DISCARDABLE        0x02000000

/* ── Crash resolution types ─────────────────────────────────────────────── */

/* Symbol entry for crash address lookup (built during CoffLoad) */
typedef struct _CoffSymEntry {
    uintptr_t addr;         /* Absolute address in loaded image */
    char      name[128];    /* Symbol name (truncated if longer) */
    uint16_t  section;      /* 1-based section number */
} CoffSymEntry;

/* Section info for crash address lookup */
typedef struct _CoffSectionInfo {
    char      name[64];     /* Resolved section name */
    uintptr_t start;        /* Start address in loaded image */
    size_t    size;          /* Raw data size */
    uint32_t  characteristics;
    char      protection[4]; /* R, RW, or RX */
} CoffSectionInfo;

typedef struct _CoffImportInfo {
    char      symbol[256];
    char      provider[64];
    char      dispatch[16];  /* pointer_slot, trampoline, or direct */
    uintptr_t address;
    int       resolved;
} CoffImportInfo;

/* One x64 dynamic function-table registration backed by a loaded .pdata
 * section.  The table memory remains owned by imageBase. */
typedef struct _CoffUnwindRegistration {
    void*    table;
    uint32_t entryCount;
} CoffUnwindRegistration;

/* Crash resolution result */
typedef struct _CoffCrashInfo {
    int  resolved;           /* 1 if address was in COFF image */
    char symbolName[128];    /* Nearest symbol name */
    int  symbolOffset;       /* Bytes past the symbol start */
    char sectionName[64];    /* Section name */
    int  sectionIndex;       /* 0-based section index */
    int  sectionOffset;      /* Bytes into the section */
} CoffCrashInfo;

/* ── Import validation types ────────────────────────────────────────────── */

typedef struct _CoffUnresolvedImport {
    char symbol[256];     /* Full COFF symbol (e.g., "__imp_NTDLL$RtlGetVersion") */
    char library[64];     /* Parsed DLL name (e.g., "NTDLL") */
    char function[128];   /* Parsed function name (e.g., "RtlGetVersion") */
    char diagnostic[256]; /* Fix suggestion (e.g., "add DFR(MSVCRT, wcscmp)") */
    int  kind;            /* 0=missing DFR, 1=COMDAT GUID, 2=RTTI, 3=string pool, 4=unknown */
} CoffUnresolvedImport;

/* ── CoffHandle — Multi-command API ─────────────────────────────────────── *
 * CoffLoad() loads and relocates a COFF once.  The caller invokes
 * handle.entry() as many times as needed with different argument buffers.
 * BeaconAddValue state persists across calls.  CoffFree() releases the
 * code pages when done. */
typedef void(__cdecl *coff_entry_fn)(char*, unsigned long);

typedef struct _CoffHandle {
    char*          imageBase;    /* Contiguous VirtualAlloc (sections + GOT) */
    size_t         imageSize;    /* Total size of contiguous block */
    coff_entry_fn  entry;        /* Resolved entry function pointer */

    /* Symbol table for crash resolution (sorted by address) */
    CoffSymEntry*     symbols;
    int               symbolCount;
    CoffSectionInfo*  sections;
    int               sectionCount;

    CoffImportInfo* imports;
    int             importCount;
    size_t          relocationCount;
    int             pointerSlotCount;
    int             trampolineCount;
    int             directImportCount;

    /* Registered x64 unwind metadata.  RtlDeleteFunctionTable must run
     * before imageBase is released. */
    CoffUnwindRegistration* unwindRegistrations;
    int                     unwindRegistrationCount;
    int                     pdataSectionCount;
    uint32_t                unwindFunctionCount;

    char errorPhase[32];
    char errorCode[64];
    char errorMessage[256];

    /* Unresolved imports (populated even when CoffLoad fails).
     * Caller should always call CoffFree after CoffLoad returns. */
    CoffUnresolvedImport* unresolvedImports;
    int                   unresolvedCount;
} CoffHandle;

/* ── Public API ─────────────────────────────────────────────────────────── */

/* Load and relocate a COFF, resolve the named entry function.
 * On success (return 0), caller must eventually call CoffFree().
 * On failure, no cleanup needed. */
int CoffLoad(char* functionname, unsigned char* coff_data,
             uint32_t filesize, CoffHandle* handle);

/* Release code pages.  After this, any pointers into the COFF
 * (including COM vtable entries built by the BOF) are invalid. */
void CoffFree(CoffHandle* handle);

/* Resolve a crash address to the nearest COFF symbol + section.
 * Returns 1 if the address falls within the COFF image, 0 otherwise. */
int CoffResolveAddress(CoffHandle* handle, uintptr_t addr, CoffCrashInfo* info);

#endif /* COFFLOADER_H_ */
