#ifndef BOF_CLI_H_
#define BOF_CLI_H_

#include <stdint.h>

#define BOF_MAX_COMMANDS 64

#define BOF_CLI_ERROR (-1)
#define BOF_CLI_OK 0
#define BOF_CLI_HELP 1

typedef struct _BofCommand {
    uint8_t* args;
    int argSize;
} BofCommand;

typedef struct _BofCliOptions {
    int jsonMode;
    int traceMode;
    int multiMode;
    int quietMode;
    int inspectMode;
    const char* entryFunction;
    const char* bofPath;
    BofCommand commands[BOF_MAX_COMMANDS];
    int commandCount;
} BofCliOptions;

int BofCliParse(int argc, char** argv, BofCliOptions* options);
void BofCliFree(BofCliOptions* options);

uint8_t* BofReadFile(const char* path, int* outLength);
int BofSha256Hex(const uint8_t* data, int length, char output[65]);

#endif
