# General-Purpose COFFLoader — Build with MSVC
#
# Usage (from VS Developer Command Prompt):
#   nmake              Build coffloader.exe
#   nmake debug        Build with debug symbols + DEBUG_PRINT output
#   nmake clean        Remove build artifacts
#
# Or directly:
#   cl /Fe:coffloader.exe src\main.c src\bof_cli.c src\json_output.c src\crash_guard.c src\coffloader.c src\beacon_compat.c /link advapi32.lib

CC = cl
OUTDIR = dist
TARGET = $(OUTDIR)\coffloader.exe

# Release flags
CFLAGS = /nologo /O2 /W3

# Debug flags
DEBUGCFLAGS = /nologo /Zi /Od /W3 /DDEBUG

# Link libraries (advapi32 for token functions)
LIBS = advapi32.lib

OBJECTS = $(OUTDIR)\main.obj $(OUTDIR)\bof_cli.obj $(OUTDIR)\json_output.obj $(OUTDIR)\crash_guard.obj $(OUTDIR)\coffloader.obj $(OUTDIR)\beacon_compat.obj
DEBUG_OBJECTS = $(OUTDIR)\main_d.obj $(OUTDIR)\bof_cli_d.obj $(OUTDIR)\json_output_d.obj $(OUTDIR)\crash_guard_d.obj $(OUTDIR)\coffloader_d.obj $(OUTDIR)\beacon_compat_d.obj

# MinGW is used to build compatibility fixtures, not the loader executable.
MINGW_CC = x86_64-w64-mingw32-gcc
MINGW_TEST_FLAGS = -c -O0 -fno-builtin -fno-stack-protector

all: $(OUTDIR) $(TARGET)
	@echo [+] Built $(TARGET)

$(OUTDIR):
	@if not exist $(OUTDIR) mkdir $(OUTDIR)

$(TARGET): $(OBJECTS)
	$(CC) /nologo /Fe:$(TARGET) $(OBJECTS) /link $(LIBS)

$(OUTDIR)\main.obj: src\main.c src\bof_cli.h src\json_output.h src\crash_guard.h src\coffloader.h src\beacon_compat.h
	$(CC) $(CFLAGS) /c /Fo:$@ src\main.c

$(OUTDIR)\bof_cli.obj: src\bof_cli.c src\bof_cli.h
	$(CC) $(CFLAGS) /c /Fo:$@ src\bof_cli.c

$(OUTDIR)\json_output.obj: src\json_output.c src\json_output.h src\crash_guard.h src\coffloader.h
	$(CC) $(CFLAGS) /c /Fo:$@ src\json_output.c

$(OUTDIR)\crash_guard.obj: src\crash_guard.c src\crash_guard.h src\coffloader.h
	$(CC) $(CFLAGS) /c /Fo:$@ src\crash_guard.c

$(OUTDIR)\coffloader.obj: src\coffloader.c src\coffloader.h src\beacon_compat.h
	$(CC) $(CFLAGS) /c /Fo:$@ src\coffloader.c

$(OUTDIR)\beacon_compat.obj: src\beacon_compat.c src\beacon_compat.h
	$(CC) $(CFLAGS) /c /Fo:$@ src\beacon_compat.c

debug: $(OUTDIR)
	$(CC) $(DEBUGCFLAGS) /c /Fo:$(OUTDIR)\main_d.obj src\main.c
	$(CC) $(DEBUGCFLAGS) /c /Fo:$(OUTDIR)\bof_cli_d.obj src\bof_cli.c
	$(CC) $(DEBUGCFLAGS) /c /Fo:$(OUTDIR)\json_output_d.obj src\json_output.c
	$(CC) $(DEBUGCFLAGS) /c /Fo:$(OUTDIR)\crash_guard_d.obj src\crash_guard.c
	$(CC) $(DEBUGCFLAGS) /c /Fo:$(OUTDIR)\coffloader_d.obj src\coffloader.c
	$(CC) $(DEBUGCFLAGS) /c /Fo:$(OUTDIR)\beacon_compat_d.obj src\beacon_compat.c
	$(CC) /nologo /Fe:$(OUTDIR)\coffloader_debug.exe $(DEBUG_OBJECTS) /link /DEBUG $(LIBS)
	@echo [+] Built $(OUTDIR)\coffloader_debug.exe

mingw-fixtures:
	$(MINGW_CC) $(MINGW_TEST_FLAGS) -o test\mingw_bare_function.x64.o test\mingw_bare_function.c
	$(MINGW_CC) $(MINGW_TEST_FLAGS) -o test\mingw_bare_data.x64.o test\mingw_bare_data.c
	$(MINGW_CC) $(MINGW_TEST_FLAGS) -o test\kv_store.x64.o test\kv_store.c
	$(MINGW_CC) $(MINGW_TEST_FLAGS) -o test\callback_error.x64.o test\callback_error.c

test: all mingw-fixtures
	$(CC) /nologo /LD /W3 /Fe:test\exception_helper.dll /Fo:test\exception_helper.obj test\exception_helper.c /link /IMPLIB:test\exception_helper.lib
	$(CC) /nologo /c /GS- /W3 /Fo:test\crashtest.x64.o test\crashtest.c
	$(CC) /nologo /c /GS- /W3 /Fo:test\badimport.x64.o test\badimport.c
	$(CC) /nologo /c /GS- /W3 /Fo:test\software_exception.x64.o test\software_exception.c
	python test\test_regressions.py

clean:
	@if exist $(OUTDIR) rmdir /s /q $(OUTDIR)
	@if exist test\exception_helper.dll del /q test\exception_helper.dll
	@if exist test\exception_helper.exp del /q test\exception_helper.exp
	@if exist test\exception_helper.lib del /q test\exception_helper.lib
	@if exist test\exception_helper.obj del /q test\exception_helper.obj
	@if exist test\software_exception.x64.o del /q test\software_exception.x64.o
	@if exist test\crashtest.x64.o del /q test\crashtest.x64.o
	@if exist test\badimport.x64.o del /q test\badimport.x64.o
	@if exist test\mingw_bare_function.x64.o del /q test\mingw_bare_function.x64.o
	@if exist test\mingw_bare_data.x64.o del /q test\mingw_bare_data.x64.o
	@if exist test\kv_store.x64.o del /q test\kv_store.x64.o
	@if exist test\callback_error.x64.o del /q test\callback_error.x64.o
	@echo [+] Clean
