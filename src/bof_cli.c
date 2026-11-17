#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif

#include "bof_cli.h"

typedef struct _PackBuffer {
    uint8_t* data;
    int length;
    int capacity;
} PackBuffer;

static void pack_init(PackBuffer* buffer) {
    memset(buffer, 0, sizeof(*buffer));
}

static void pack_free(PackBuffer* buffer) {
    free(buffer->data);
    memset(buffer, 0, sizeof(*buffer));
}

static int pack_grow(PackBuffer* buffer, int needed) {
    int new_capacity;
    uint8_t* resized;

    if (needed < 0 || buffer->length > INT_MAX - needed) return 0;
    if (buffer->length + needed <= buffer->capacity) return 1;
    new_capacity = buffer->capacity ? buffer->capacity * 2 : 256;
    while (new_capacity < buffer->length + needed) {
        if (new_capacity > INT_MAX / 2) return 0;
        new_capacity *= 2;
    }
    resized = (uint8_t*)realloc(buffer->data, (size_t)new_capacity);
    if (resized == NULL) return 0;
    buffer->data = resized;
    buffer->capacity = new_capacity;
    return 1;
}

static int pack_append(PackBuffer* buffer, const void* source, int length) {
    if (!pack_grow(buffer, length)) return 0;
    memcpy(buffer->data + buffer->length, source, (size_t)length);
    buffer->length += length;
    return 1;
}

static int pack_u32(PackBuffer* buffer, uint32_t value) {
    return pack_append(buffer, &value, sizeof(value));
}

static int hex_nibble(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static uint8_t* decode_hex(const char* hex, int* out_length) {
    int string_length = (int)strlen(hex);
    int byte_length;
    uint8_t* output;

    if ((string_length & 1) != 0) return NULL;
    byte_length = string_length / 2;
    output = (uint8_t*)malloc((size_t)(byte_length ? byte_length : 1));
    if (output == NULL) return NULL;
    for (int index = 0; index < byte_length; index++) {
        int high = hex_nibble(hex[index * 2]);
        int low = hex_nibble(hex[index * 2 + 1]);
        if (high < 0 || low < 0) {
            free(output);
            return NULL;
        }
        output[index] = (uint8_t)((high << 4) | low);
    }
    *out_length = byte_length;
    return output;
}

uint8_t* BofReadFile(const char* path, int* out_length) {
    FILE* file = NULL;
    long file_size;
    uint8_t* contents;
    size_t bytes_read;

    if (path == NULL || out_length == NULL) return NULL;
    *out_length = 0;
    if (fopen_s(&file, path, "rb") != 0 || file == NULL) return NULL;
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }
    file_size = ftell(file);
    if (file_size <= 0 || file_size > INT_MAX || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }
    contents = (uint8_t*)malloc((size_t)file_size);
    if (contents == NULL) {
        fclose(file);
        return NULL;
    }
    bytes_read = fread(contents, 1, (size_t)file_size, file);
    fclose(file);
    if (bytes_read != (size_t)file_size) {
        free(contents);
        return NULL;
    }
    *out_length = (int)bytes_read;
    return contents;
}

int BofSha256Hex(const uint8_t* data, int length, char output[65]) {
#ifdef _WIN32
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    BYTE digest[32];
    DWORD digest_length = sizeof(digest);
    static const char hex[] = "0123456789abcdef";
    int ok = 0;

    output[0] = '\0';
    if (data == NULL || length < 0) return 0;
    if (!CryptAcquireContextA(&provider, NULL, NULL, PROV_RSA_AES,
                              CRYPT_VERIFYCONTEXT)) goto cleanup;
    if (!CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) goto cleanup;
    if (!CryptHashData(hash, data, (DWORD)length, 0)) goto cleanup;
    if (!CryptGetHashParam(hash, HP_HASHVAL, digest, &digest_length, 0)
        || digest_length != sizeof(digest)) goto cleanup;

    for (int index = 0; index < 32; index++) {
        output[index * 2] = hex[digest[index] >> 4];
        output[index * 2 + 1] = hex[digest[index] & 0x0F];
    }
    output[64] = '\0';
    ok = 1;

cleanup:
    if (hash) CryptDestroyHash(hash);
    if (provider) CryptReleaseContext(provider, 0);
    return ok;
#else
    (void)data;
    (void)length;
    output[0] = '\0';
    return 0;
#endif
}

static int pack_argument(const char* spec, PackBuffer* buffer) {
    char type;
    const char* value;

    if (spec == NULL || strlen(spec) < 2 || spec[1] != ':') {
        fprintf(stderr, "[!] Invalid arg spec: '%s' (expected type:value)\n",
                spec ? spec : "(null)");
        return 0;
    }
    type = spec[0];
    value = spec + 2;

    switch (type) {
    case 'i': {
        int32_t number = (int32_t)strtol(value, NULL, 0);
        return pack_append(buffer, &number, sizeof(number));
    }
    case 's': {
        int16_t number = (int16_t)strtol(value, NULL, 0);
        return pack_append(buffer, &number, sizeof(number));
    }
    case 'z': {
        uint32_t length = (uint32_t)strlen(value) + 1;
        return pack_u32(buffer, length)
            && pack_append(buffer, value, (int)length);
    }
    case 'Z': {
#ifdef _WIN32
        int characters = MultiByteToWideChar(CP_UTF8, 0, value, -1, NULL, 0);
        wchar_t* wide;
        uint32_t byte_length;
        int ok;
        if (characters <= 0) {
            fprintf(stderr, "[!] UTF-8 to wide conversion failed\n");
            return 0;
        }
        wide = (wchar_t*)malloc((size_t)characters * sizeof(wchar_t));
        if (wide == NULL) return 0;
        if (!MultiByteToWideChar(CP_UTF8, 0, value, -1, wide, characters)) {
            free(wide);
            return 0;
        }
        byte_length = (uint32_t)((size_t)characters * sizeof(wchar_t));
        ok = pack_u32(buffer, byte_length)
            && pack_append(buffer, wide, (int)byte_length);
        free(wide);
        return ok;
#else
        fprintf(stderr, "[!] Wide string packing requires Windows\n");
        return 0;
#endif
    }
    case 'b': {
        uint8_t* blob = NULL;
        int blob_length = 0;
        int ok;
        if (value[0] == '@') {
            blob = BofReadFile(value + 1, &blob_length);
            if (blob == NULL) {
                fprintf(stderr, "[!] Failed to read blob file: %s\n", value + 1);
                return 0;
            }
        } else {
            blob = decode_hex(value, &blob_length);
            if (blob == NULL) {
                fprintf(stderr, "[!] Invalid hex in blob: %s\n", value);
                return 0;
            }
        }
        ok = pack_u32(buffer, (uint32_t)blob_length)
            && pack_append(buffer, blob, blob_length);
        free(blob);
        return ok;
    }
    default:
        fprintf(stderr, "[!] Unknown arg type '%c' in spec '%s'\n", type, spec);
        fprintf(stderr, "    Valid types: i, s, z, Z, b\n");
        return 0;
    }
}

static uint8_t* finalize_packed(PackBuffer* buffer, int* out_length) {
    int total;
    if (buffer == NULL || out_length == NULL || buffer->length < 0
        || buffer->length > INT_MAX - 4) {
        return NULL;
    }
    total = 4 + buffer->length;
    uint32_t total_size = (uint32_t)total;
    uint8_t* output = (uint8_t*)malloc((size_t)total);
    if (output == NULL) return NULL;
    memcpy(output, &total_size, sizeof(total_size));
    if (buffer->length > 0)
        memcpy(output + 4, buffer->data, (size_t)buffer->length);
    *out_length = total;
    return output;
}

static void print_usage(const char* program) {
    fprintf(stderr,
        "General-Purpose BOF Test Harness (COFFLoader)\n\n"
        "Usage:\n  %s [options] <entry> <bof_file> [arg_spec ...]\n\n"
        "Options:\n"
        "  --json        Structured JSON output\n"
        "  --inspect     Parse, resolve, and report without executing\n"
        "  --trace       Log every Beacon API call (included in JSON)\n"
        "  --multi       Multi-command mode (-- separates commands)\n"
        "  --hex <hex>   Raw hex args (repeatable for multi-command)\n"
        "  --quiet       Suppress COFFLoader banner\n"
        "  --help        Show this help\n\n"
        "Arg specs: i:<int> s:<short> z:<ansi> Z:<utf8> b:<hex> b:@<file>\n\n"
        "Examples:\n"
        "  %s go mybof.o i:0\n"
        "  %s --multi go mybof.o i:0 -- i:2 Z:whoami -- i:3\n"
        "  %s --json go mybof.o i:0\n"
        "  %s --inspect go mybof.o\n",
        program, program, program, program, program);
}

static int add_packed_command(BofCliOptions* options, PackBuffer* buffer) {
    BofCommand* command;
    if (options->commandCount >= BOF_MAX_COMMANDS) {
        fprintf(stderr, "[!] Too many commands (maximum %d)\n", BOF_MAX_COMMANDS);
        return 0;
    }
    command = &options->commands[options->commandCount];
    command->args = finalize_packed(buffer, &command->argSize);
    if (command->args == NULL) return 0;
    options->commandCount++;
    return 1;
}

int BofCliParse(int argc, char** argv, BofCliOptions* options) {
    int argument = 1;
    int has_hex = 0;

    if (options == NULL) return BOF_CLI_ERROR;
    memset(options, 0, sizeof(*options));

    while (argument < argc && argv[argument][0] == '-'
           && argv[argument][1] == '-') {
        if (strcmp(argv[argument], "--json") == 0) options->jsonMode = 1;
        else if (strcmp(argv[argument], "--inspect") == 0) {
            options->inspectMode = 1;
            options->jsonMode = 1;
        } else if (strcmp(argv[argument], "--trace") == 0) options->traceMode = 1;
        else if (strcmp(argv[argument], "--multi") == 0) options->multiMode = 1;
        else if (strcmp(argv[argument], "--quiet") == 0) options->quietMode = 1;
        else if (strcmp(argv[argument], "--help") == 0) {
            print_usage(argv[0]);
            return BOF_CLI_HELP;
        } else if (strcmp(argv[argument], "--hex") == 0
                   || strcmp(argv[argument], "--") == 0) {
            break;
        } else {
            fprintf(stderr, "[!] Unknown option: %s\n", argv[argument]);
            return BOF_CLI_ERROR;
        }
        argument++;
    }

    if (argument >= argc) {
        print_usage(argv[0]);
        return BOF_CLI_ERROR;
    }
    options->entryFunction = argv[argument++];
    if (argument >= argc) {
        print_usage(argv[0]);
        return BOF_CLI_ERROR;
    }
    options->bofPath = argv[argument++];

    for (int index = argument; index < argc; index++) {
        if (strcmp(argv[index], "--hex") == 0) {
            has_hex = 1;
            break;
        }
    }

    if (has_hex) {
        while (argument < argc) {
            BofCommand* command;
            if (options->commandCount >= BOF_MAX_COMMANDS) goto too_many;
            if (strcmp(argv[argument++], "--hex") != 0) {
                fprintf(stderr, "[!] Expected --hex\n");
                goto error;
            }
            if (argument >= argc) {
                fprintf(stderr, "[!] --hex requires a hex string\n");
                goto error;
            }
            command = &options->commands[options->commandCount];
            command->args = decode_hex(argv[argument], &command->argSize);
            if (command->args == NULL && argv[argument][0] != '\0') {
                fprintf(stderr, "[!] Invalid hex string: %s\n", argv[argument]);
                goto error;
            }
            options->commandCount++;
            argument++;
        }
    } else if (options->multiMode) {
        PackBuffer buffer;
        int in_command = 0;
        pack_init(&buffer);
        while (argument <= argc) {
            int separator = argument == argc || strcmp(argv[argument], "--") == 0;
            if (separator) {
                if (in_command || buffer.length > 0) {
                    if (!add_packed_command(options, &buffer)) {
                        pack_free(&buffer);
                        goto error;
                    }
                    pack_free(&buffer);
                    pack_init(&buffer);
                    in_command = 0;
                }
                argument++;
            } else {
                if (!pack_argument(argv[argument], &buffer)) {
                    pack_free(&buffer);
                    goto error;
                }
                in_command = 1;
                argument++;
            }
        }
        pack_free(&buffer);
    } else {
        PackBuffer buffer;
        pack_init(&buffer);
        while (argument < argc) {
            if (!pack_argument(argv[argument++], &buffer)) {
                pack_free(&buffer);
                goto error;
            }
        }
        if (!add_packed_command(options, &buffer)) {
            pack_free(&buffer);
            goto error;
        }
        pack_free(&buffer);
    }

    if (options->commandCount == 0) {
        fprintf(stderr, "[!] No commands to execute\n");
        goto error;
    }
    return BOF_CLI_OK;

too_many:
    fprintf(stderr, "[!] Too many commands (maximum %d)\n", BOF_MAX_COMMANDS);
error:
    BofCliFree(options);
    return BOF_CLI_ERROR;
}

void BofCliFree(BofCliOptions* options) {
    if (options == NULL) return;
    for (int index = 0; index < options->commandCount; index++) {
        free(options->commands[index].args);
        options->commands[index].args = NULL;
        options->commands[index].argSize = 0;
    }
    options->commandCount = 0;
}
