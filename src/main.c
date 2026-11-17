/*
 * General-purpose BOF test harness CLI.
 *
 * main.c intentionally contains only run orchestration. Command parsing and
 * packing live in bof_cli.c, JSON serialization in json_output.c, native
 * fault recovery in crash_guard.c, COFF loading in coffloader.c, and Beacon
 * compatibility in beacon_compat.c.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include "beacon_compat.h"
#include "bof_cli.h"
#include "coffloader.h"
#include "crash_guard.h"
#include "json_output.h"

static void print_unresolved_json(const char* run_id,
                                  const BofCliOptions* options,
                                  int bof_size, const char* artifact_sha256,
                                  const CoffHandle* handle) {
    static const char* kinds[] = {
        "missing_dfr", "comdat_guid", "rtti", "string_pool", "unknown"
    };
    const char* message = handle->errorMessage[0]
        ? handle->errorMessage : "One or more imports could not be resolved";

    JsonPrintEnvelopePrefix(run_id, options->bofPath, bof_size, artifact_sha256);
    printf(",\"status\":\"error\",\"legacy_status\":\"unresolved_imports\"," 
           "\"phase\":\"%s\",\"error\":{\"code\":\"%s\",\"message\":",
           handle->errorPhase[0] ? handle->errorPhase : "resolve",
           handle->errorCode[0] ? handle->errorCode : "COFF_UNRESOLVED_IMPORTS");
    JsonPrintString(stdout, message, (int)strlen(message));
    printf("},\"unresolved\":[");
    for (int index = 0; index < handle->unresolvedCount; index++) {
        const CoffUnresolvedImport* unresolved = &handle->unresolvedImports[index];
        int kind = unresolved->kind;
        if (kind < 0 || kind > 4) kind = 4;
        if (index) printf(",");
        printf("{\"symbol\":");
        JsonPrintString(stdout, unresolved->symbol,
                        (int)strlen(unresolved->symbol));
        printf(",\"kind\":\"%s\"", kinds[kind]);
        if (unresolved->library[0]) {
            printf(",\"library\":");
            JsonPrintString(stdout, unresolved->library,
                            (int)strlen(unresolved->library));
        }
        if (unresolved->function[0]) {
            printf(",\"function\":");
            JsonPrintString(stdout, unresolved->function,
                            (int)strlen(unresolved->function));
        }
        if (unresolved->diagnostic[0]) {
            printf(",\"fix\":");
            JsonPrintString(stdout, unresolved->diagnostic,
                            (int)strlen(unresolved->diagnostic));
        }
        printf("}");
    }
    printf("],\"inspection\":");
    JsonPrintInspection(handle);
    printf("}\n");
}

static void print_unresolved_text(const CoffHandle* handle) {
    static const char* labels[] = {
        "MISSING_DFR", "COMDAT_GUID", "RTTI", "STRING_POOL", "UNKNOWN"
    };

    fprintf(stderr, "[!] CoffLoad failed: %d unresolved symbol(s):\n",
            handle->unresolvedCount);
    for (int index = 0; index < handle->unresolvedCount; index++) {
        const CoffUnresolvedImport* unresolved = &handle->unresolvedImports[index];
        int kind = unresolved->kind;
        if (kind < 0 || kind > 4) kind = 4;
        fprintf(stderr, "    [%d] (%s) %s", index + 1, labels[kind],
                unresolved->symbol);
        if (unresolved->library[0]) {
            fprintf(stderr, "  (library: %s", unresolved->library);
            if (unresolved->function[0])
                fprintf(stderr, ", function: %s", unresolved->function);
            fprintf(stderr, ")");
        }
        fprintf(stderr, "\n");
        if (unresolved->diagnostic[0])
            fprintf(stderr, "         Fix: %s\n", unresolved->diagnostic);
    }
}

static void print_load_error_json(const char* run_id,
                                  const BofCliOptions* options,
                                  int bof_size, const char* artifact_sha256,
                                  const CoffHandle* handle) {
    const char* phase = handle->errorPhase[0] ? handle->errorPhase : "load";
    const char* code = handle->errorCode[0]
        ? handle->errorCode : "COFF_LOAD_FAILED";
    const char* message = handle->errorMessage[0]
        ? handle->errorMessage : "COFF loading failed";

    JsonPrintEnvelopePrefix(run_id, options->bofPath, bof_size, artifact_sha256);
    printf(",\"status\":\"error\",\"legacy_status\":\"load_error\"," 
           "\"phase\":\"%s\",\"error\":{\"code\":\"%s\",\"message\":",
           phase, code);
    JsonPrintString(stdout, message, (int)strlen(message));
    printf("},\"inspection\":");
    JsonPrintInspection(handle);
    printf("}\n");
}

static void close_output_pipe(void) {
    fflush(stdout);
#ifdef _WIN32
    FlushFileBuffers(GetStdHandle(STD_OUTPUT_HANDLE));
    CloseHandle(GetStdHandle(STD_OUTPUT_HANDLE));
#endif
    fclose(stdout);
}

int main(int argc, char** argv) {
    BofCliOptions options;
    int cli_result;
    char run_id[64] = {0};
    char artifact_sha256[65] = {0};
    int bof_size = 0;
    uint8_t* bof_data = NULL;
    CoffHandle handle = {0};
    int load_result;
    int any_crash = 0;
    int callback_error_count = 0;
    int json_first = 1;

    setvbuf(stdout, NULL, _IONBF, 0);
#ifdef _WIN32
    snprintf(run_id, sizeof(run_id), "%lu-%llu", GetCurrentProcessId(),
             (unsigned long long)GetTickCount64());
#else
    snprintf(run_id, sizeof(run_id), "local-run");
#endif

    cli_result = BofCliParse(argc, argv, &options);
    if (cli_result == BOF_CLI_HELP) return 0;
    if (cli_result != BOF_CLI_OK) return 1;

    bof_data = BofReadFile(options.bofPath, &bof_size);
    if (bof_data == NULL || bof_size == 0) {
        if (options.jsonMode) {
            JsonPrintEnvelopePrefix(run_id, options.bofPath, 0, "");
            printf(",\"status\":\"error\",\"phase\":\"input\"," 
                   "\"error\":{\"code\":\"INPUT_READ_FAILED\"," 
                   "\"message\":\"Failed to read BOF input\"}}\n");
        } else {
            fprintf(stderr, "[!] Failed to read BOF: %s\n", options.bofPath);
        }
        BofCliFree(&options);
        return 1;
    }
    (void)BofSha256Hex(bof_data, bof_size, artifact_sha256);

    if (options.jsonMode) {
        extern int g_suppressStdout;
        g_suppressStdout = 1;
    }
    if (options.traceMode) {
        extern int g_traceEnabled;
        g_traceEnabled = 1;
    }
    if (!options.quietMode && !options.jsonMode)
        printf("BOF: %s (%d bytes)\n", options.bofPath, bof_size);

    load_result = CoffLoad((char*)options.entryFunction, bof_data,
                           (uint32_t)bof_size, &handle);
    if (load_result != 0 || handle.entry == NULL) {
        if (handle.unresolvedCount > 0) {
            if (options.jsonMode)
                print_unresolved_json(run_id, &options, bof_size,
                                      artifact_sha256, &handle);
            else
                print_unresolved_text(&handle);
        } else if (options.jsonMode) {
            print_load_error_json(run_id, &options, bof_size,
                                  artifact_sha256, &handle);
        } else {
            fprintf(stderr, "[!] CoffLoad failed (rc=%d)\n", load_result);
        }
        CoffFree(&handle);
        BofCliFree(&options);
        free(bof_data);
        return 1;
    }

    if (options.inspectMode) {
        JsonPrintEnvelopePrefix(run_id, options.bofPath, bof_size,
                                artifact_sha256);
        printf(",\"status\":\"ok\",\"phase\":\"inspect\",\"inspection\":");
        JsonPrintInspection(&handle);
        printf("}\n");
        CoffFree(&handle);
        BofCliFree(&options);
        free(bof_data);
        return 0;
    }

    if (!options.quietMode && !options.jsonMode) {
        printf("COFF loaded, entry '%s' at %p, %d command(s)\n",
               options.entryFunction, handle.entry, options.commandCount);
        printf("  Image: %p - %p (%zu bytes, %d symbols)\n\n",
               handle.imageBase, handle.imageBase + handle.imageSize,
               handle.imageSize, handle.symbolCount);
    }

    if (!CrashGuardInstall()) {
        if (options.jsonMode) {
            JsonPrintEnvelopePrefix(run_id, options.bofPath, bof_size,
                                    artifact_sha256);
            printf(",\"status\":\"error\",\"phase\":\"execute\"," 
                   "\"error\":{\"code\":\"CRASH_GUARD_INSTALL_FAILED\"," 
                   "\"message\":\"Failed to install crash handler\"}}\n");
        } else {
            fprintf(stderr, "[!] Failed to install crash handler\n");
        }
        CoffFree(&handle);
        BofCliFree(&options);
        free(bof_data);
        return 1;
    }

    if (options.jsonMode) {
        JsonPrintEnvelopePrefix(run_id, options.bofPath, bof_size,
                                artifact_sha256);
        printf(",\"status\":\"completed\",\"phase\":\"execute\",\"commands\":[");
    }

    for (int index = 0; index < options.commandCount; index++) {
        CrashDetails crash = {0};
        CoffCrashInfo crash_resolution = {0};
        int crashed;
        int output_size = 0;
        char* output;
        int command_callback_errors;
        int trace_size = 0;
        char* trace = NULL;

        BeaconResetOutput();
        BeaconResetTrace();
        if (!options.jsonMode && options.commandCount > 1) {
            printf(">>> CMD %d/%d <<<\n", index + 1, options.commandCount);
            fflush(stdout);
        }

        crashed = CrashGuardExecute(handle.entry,
                                    (char*)options.commands[index].args,
                                    (unsigned long)options.commands[index].argSize,
                                    &crash);
        if (crashed) any_crash++;

        fflush(stdout);
#ifdef _WIN32
        FlushFileBuffers(GetStdHandle(STD_OUTPUT_HANDLE));
#endif

        output = BeaconGetOutputData(&output_size);
        command_callback_errors = BeaconGetErrorCount();
        callback_error_count += command_callback_errors;
        if (options.traceMode) trace = BeaconGetTraceData(&trace_size);

        if (crashed && crash.instructionAddress)
            CoffResolveAddress(&handle, crash.instructionAddress,
                               &crash_resolution);

        if (options.jsonMode) {
            if (!json_first) printf(",");
            json_first = 0;
            JsonPrintCommandResult(index, crashed, &crash, &crash_resolution,
                                   command_callback_errors, output, output_size,
                                   trace, trace_size);
        } else if (crashed) {
            PrintCrashResult(&crash, &crash_resolution, index);
        } else if (command_callback_errors > 0) {
            printf("\n[!] BOF reported %d CALLBACK_ERROR message(s) in command %d\n",
                   command_callback_errors, index + 1);
        }

        if (!options.jsonMode && options.traceMode && trace)
            printf("[TRACE] %s\n", trace);
        free(output);
        free(trace);
    }

    if (options.jsonMode) {
        printf("],\"summary\":{\"ok\":%s,\"command_count\":%d," 
               "\"crash_count\":%d,\"callback_error_count\":%d}}\n",
               (any_crash || callback_error_count) ? "false" : "true",
               options.commandCount, any_crash, callback_error_count);
    } else if (!options.quietMode && options.commandCount > 1) {
        printf("\n%d command(s) executed", options.commandCount);
        if (any_crash) printf(" (%d crashed)", any_crash);
        if (callback_error_count)
            printf(" (%d callback errors)", callback_error_count);
        printf("\n");
    }

    close_output_pipe();
    CrashGuardRemove();
    CoffFree(&handle);
    BofCliFree(&options);
    free(bof_data);
    return (any_crash || callback_error_count) ? 1 : 0;
}
