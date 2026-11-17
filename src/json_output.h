#ifndef JSON_OUTPUT_H_
#define JSON_OUTPUT_H_

#include <stdio.h>

#include "coffloader.h"
#include "crash_guard.h"

void JsonPrintString(FILE* stream, const char* value, int length);
void JsonPrintEnvelopePrefix(const char* run_id, const char* path,
                             int size, const char* sha256);
void JsonPrintInspection(const CoffHandle* handle);
void JsonPrintCommandResult(int index, int crashed,
                            const CrashDetails* crash,
                            const CoffCrashInfo* resolution,
                            int callback_errors,
                            const char* output, int output_size,
                            const char* trace, int trace_size);
void PrintCrashResult(const CrashDetails* crash,
                      const CoffCrashInfo* resolution, int command_index);

#endif
