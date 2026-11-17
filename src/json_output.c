#include <stdio.h>
#include <string.h>

#include "json_output.h"

void JsonPrintString(FILE* stream, const char* value, int length) {
    fputc('"', stream);
    for (int index = 0; index < length; index++) {
        unsigned char character = (unsigned char)value[index];
        switch (character) {
        case '"': fputs("\\\"", stream); break;
        case '\\': fputs("\\\\", stream); break;
        case '\n': fputs("\\n", stream); break;
        case '\r': fputs("\\r", stream); break;
        case '\t': fputs("\\t", stream); break;
        case '\0': break;
        default:
            if (character < 0x20) fprintf(stream, "\\u%04x", character);
            else fputc(character, stream);
            break;
        }
    }
    fputc('"', stream);
}

void JsonPrintEnvelopePrefix(const char* run_id, const char* path,
                             int size, const char* sha256) {
    printf("{\"schema\":\"%s\",\"schema_version\":%d,\"run_id\":",
           COFFLOADER_JSON_SCHEMA_ID, COFFLOADER_JSON_SCHEMA_VERSION);
    JsonPrintString(stdout, run_id, (int)strlen(run_id));
    printf(",\"loader\":{\"version\":\"%s\",\"build\":",
           COFFLOADER_VERSION);
    JsonPrintString(stdout, __DATE__ " " __TIME__,
                    (int)strlen(__DATE__ " " __TIME__));
    printf("},\"artifact\":{\"path\":");
    JsonPrintString(stdout, path ? path : "", path ? (int)strlen(path) : 0);
    printf(",\"size\":%d,\"sha256\":", size);
    JsonPrintString(stdout, sha256 ? sha256 : "",
                    sha256 ? (int)strlen(sha256) : 0);
    printf("}");
}

void JsonPrintInspection(const CoffHandle* handle) {
    const char* compiler = "msvc-compatible";
    if (handle->trampolineCount > 0 || handle->directImportCount > 0)
        compiler = "mingw-compatible";

    printf("{\"compiler_profile\":\"%s\",\"image_size\":%zu",
           compiler, handle->imageSize);
    printf(",\"symbol_count\":%d,\"relocation_count\":%zu",
           handle->symbolCount, handle->relocationCount);
    printf(",\"unwind\":{\"pdata_sections\":%d,\"registered_tables\":%d,"
           "\"function_count\":%lu}",
           handle->pdataSectionCount, handle->unwindRegistrationCount,
           (unsigned long)handle->unwindFunctionCount);
    printf(",\"dispatch\":{\"pointer_slots\":%d,\"trampolines\":%d,"
           "\"direct_imports\":%d}",
           handle->pointerSlotCount, handle->trampolineCount,
           handle->directImportCount);

    printf(",\"sections\":[");
    for (int index = 0; index < handle->sectionCount; index++) {
        if (index) printf(",");
        printf("{\"index\":%d,\"name\":", index);
        JsonPrintString(stdout, handle->sections[index].name,
                        (int)strlen(handle->sections[index].name));
        printf(",\"size\":%zu,\"characteristics\":\"0x%08X\"," 
               "\"protection\":\"%s\"}",
               handle->sections[index].size,
               handle->sections[index].characteristics,
               handle->sections[index].protection);
    }
    printf("]");

    printf(",\"imports\":[");
    for (int index = 0; index < handle->importCount; index++) {
        const CoffImportInfo* entry = &handle->imports[index];
        if (index) printf(",");
        printf("{\"symbol\":");
        JsonPrintString(stdout, entry->symbol, (int)strlen(entry->symbol));
        printf(",\"resolved\":%s,\"provider\":",
               entry->resolved ? "true" : "false");
        JsonPrintString(stdout, entry->provider, (int)strlen(entry->provider));
        printf(",\"dispatch\":\"%s\",\"address\":\"0x%llX\"}",
               entry->dispatch, (unsigned long long)entry->address);
    }
    printf("]}");
}

void JsonPrintCommandResult(int index, int crashed,
                            const CrashDetails* crash,
                            const CoffCrashInfo* resolution,
                            int callback_errors,
                            const char* output, int output_size,
                            const char* trace, int trace_size) {
    printf("{\"index\":%d", index);
    if (crashed) {
        printf(",\"status\":\"crash\",\"exception\":\"0x%08lX\"",
               (unsigned long)crash->code);
        printf(",\"exception_name\":\"%s\"", CrashExceptionName(crash->code));
        printf(",\"error\":{\"code\":\"BOF_EXCEPTION\"," 
               "\"phase\":\"execute\",\"message\":"
               "\"BOF raised a hardware exception\"}");
        printf(",\"fault_addr\":\"0x%llX\"",
               (unsigned long long)crash->instructionAddress);
        printf(",\"exception_parameters\":[");
        for (uint32_t parameter = 0; parameter < crash->parameterCount; parameter++) {
            if (parameter) printf(",");
            printf("\"0x%llX\"", (unsigned long long)crash->parameters[parameter]);
        }
        printf("]");
        if (CrashHasMemoryAccess(crash)) {
            printf(",\"access_type\":\"%s\",\"access_addr\":\"0x%llX\"",
                   CrashAccessType(crash),
                   (unsigned long long)CrashAccessAddress(crash));
            if (CrashInPageStatus(crash) != 0) {
                printf(",\"in_page_status\":\"0x%08llX\"",
                       (unsigned long long)CrashInPageStatus(crash));
            }
        }
        if (resolution->resolved) {
            if (resolution->symbolName[0]) {
                printf(",\"nearest_symbol\":");
                JsonPrintString(stdout, resolution->symbolName,
                                (int)strlen(resolution->symbolName));
                printf(",\"symbol_offset\":%d", resolution->symbolOffset);
            }
            if (resolution->sectionName[0]) {
                printf(",\"section\":");
                JsonPrintString(stdout, resolution->sectionName,
                                (int)strlen(resolution->sectionName));
                printf(",\"section_index\":%d,\"section_offset\":%d",
                       resolution->sectionIndex, resolution->sectionOffset);
            }
            printf(",\"in_bof\":true");
        } else {
            printf(",\"in_bof\":false");
        }
    } else if (callback_errors > 0) {
        printf(",\"status\":\"error\",\"callback_error_count\":%d",
               callback_errors);
        printf(",\"error\":{\"code\":\"BOF_CALLBACK_ERROR\"," 
               "\"phase\":\"execute\",\"message\":"
               "\"BOF reported CALLBACK_ERROR\"}");
    } else {
        printf(",\"status\":\"ok\"");
    }
    if (output != NULL && output_size > 0) {
        printf(",\"output\":");
        JsonPrintString(stdout, output, output_size);
    }
    if (trace != NULL && trace_size > 0) printf(",\"trace\":%s", trace);
    printf("}");
}

void PrintCrashResult(const CrashDetails* crash,
                      const CoffCrashInfo* resolution, int command_index) {
    printf("\n[!] CRASH: Exception 0x%08lX at 0x%llX",
           (unsigned long)crash->code,
           (unsigned long long)crash->instructionAddress);
    if (CrashHasMemoryAccess(crash)) {
        printf(" while attempting to %s 0x%llX", CrashAccessType(crash),
               (unsigned long long)CrashAccessAddress(crash));
    }
    if (resolution->resolved) {
        if (resolution->symbolName[0])
            printf(" (%s+0x%X)", resolution->symbolName, resolution->symbolOffset);
        if (resolution->sectionName[0])
            printf(" [%s+0x%X]", resolution->sectionName, resolution->sectionOffset);
    } else {
        printf(" (outside BOF image)");
    }
    printf(" in command %d\n", command_index + 1);
}
