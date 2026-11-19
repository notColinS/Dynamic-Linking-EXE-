#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

/* llm generated: WinTrust API for Authenticode signature verification */
#include <wintrust.h>
#include <softpub.h>
#pragma comment(lib, "wintrust.lib")

#define MAX_LINE 1024
#define MAX_ARGS 16

typedef int(__cdecl* ParseCommandFn)(char*, char* [], int);
typedef int(__cdecl* ExecuteCommandFn)(const char*, const char* const [], int); //have to use cdecl don't totally understand this

typedef struct {
    const char* linux_name;
    const char* windows_name;
    int min_args;
    int max_args;
} Command;

static const Command commands[] = {
    {"ls", "dir", 0, 1}, {"cat", "type", 1, 1},
    {"cp", "copy", 2, 2}, {"mv", "move", 2, 2},
    {"rm", "del", 1, 1}, {"mkdir", "mkdir", 1, 1},
    {"rmdir", "rmdir", 1, 1}, {"echo", "echo", 1, MAX_ARGS - 1}
};

static const Command* find_command(const char* name)
{
    size_t i;
    for (i = 0; i < sizeof(commands) / sizeof(commands[0]); ++i)
        if (strcmp(commands[i].linux_name, name) == 0)
            return &commands[i];
    return NULL;
}

static int safe_path(const char* s)
{
    const unsigned char* p = (const unsigned char*)s;
    if (!p || !*p)
        return 0;
    while (*p) {
        if (*p < 32 || *p == 127 || strchr("&|<>^*%!?()\"", *p))
            return 0;
        ++p;
    }
    return 1;
}

/* llm generated: verify a file's embedded Authenticode signature.
   Returns ERROR_SUCCESS (0) only if the file is signed AND the signing
   certificate chains to a trusted root; any other value is the failure reason. */
static LONG VerifyDllSignatureW(LPCWSTR filePath)
{
    WINTRUST_FILE_INFO fileInfo;
    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wtd;
    LONG status;

    memset(&fileInfo, 0, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath;

    memset(&wtd, 0, sizeof(wtd));
    wtd.cbStruct = sizeof(WINTRUST_DATA);
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;
    wtd.pFile = &fileInfo;

    status = WinVerifyTrust(NULL, &policyGUID, &wtd);

    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &wtd);

    return status;
}

/* llm generated: wrapper so the same ANSI path used by LoadLibraryA can be verified */
static LONG VerifyDllSignatureA(const char* ansiPath)
{
    wchar_t wide[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, ansiPath, -1, wide, MAX_PATH);
    return VerifyDllSignatureW(wide);
}

static int dispatch(char* args[], int argc, ExecuteCommandFn execute)
{
    const Command* cmd;
    if (argc == 0)
        return 0;
    if (strcmp(args[0], "exit") == 0) {
        if (argc != 1) { puts("Usage: exit"); return 1; }
        return -1;
    }
    if (strcmp(args[0], "help") == 0) {
        if (argc != 1) { puts("Usage: help"); return 1; }
        puts("Commands: ls cat pwd cd cp mv rm mkdir rmdir clear echo help exit");
        return 0;
    }
    if (strcmp(args[0], "pwd") == 0) {
        char path[MAX_PATH];
        DWORD n;
        if (argc != 1) { puts("Usage: pwd"); return 1; }
        n = GetCurrentDirectoryA(sizeof(path), path);
        if (!n || n >= sizeof(path)) { puts("Unable to read working directory."); return 1; }
        puts(path);
        return 0;
    }
    if (strcmp(args[0], "cd") == 0) {
        if (argc != 2 || !safe_path(args[1])) { puts("Usage: cd DIRECTORY"); return 1; }
        if (!SetCurrentDirectoryA(args[1])) { puts("Cannot change directory."); return 1; }
        return 0;
    }
    if (strcmp(args[0], "clear") == 0) {
        HANDLE h;
        CONSOLE_SCREEN_BUFFER_INFO info;
        DWORD cells, written;
        COORD origin = { 0, 0 };
        if (argc != 1) { puts("Usage: clear"); return 1; }
        h = GetStdHandle(STD_OUTPUT_HANDLE);
        if (!GetConsoleScreenBufferInfo(h, &info)) return 1;
        cells = (DWORD)info.dwSize.X * (DWORD)info.dwSize.Y;
        if (!FillConsoleOutputCharacterA(h, ' ', cells, origin, &written)) return 1;
        if (!FillConsoleOutputAttribute(h, info.wAttributes, cells, origin, &written)) return 1;
        if (!SetConsoleCursorPosition(h, origin)) return 1;
        return 0;
    }

    cmd = find_command(args[0]);
    if (!cmd) { puts("Unknown command. Type help."); return 1; }
    if (argc - 1 < cmd->min_args || argc - 1 > cmd->max_args) {
        puts("Incorrect number of arguments.");
        return 1;
    }
    return execute(cmd->windows_name, (const char* const*)(args + 1), argc - 1);
}

int main(void)
{
    HMODULE dll;
    ParseCommandFn parse;
    ExecuteCommandFn execute;
    char line[MAX_LINE];
    char* args[MAX_ARGS];
    int argc;
    LONG sig;                 /* llm generated */
    const char* dllPath =     /* llm generated: one path used for both the check and the load */

        "C:\\Users\\Student\\source\\repos\\L2WShell\\Debug\\L2WShellDLLM.dll"; //path needed

    /* llm generated: verify the signature before LoadLibrary; refuse to load if not trusted */
    sig = VerifyDllSignatureA(dllPath);
    if (sig != ERROR_SUCCESS) {
        fprintf(stderr, "[L2WShell] Signature check FAILED (0x%08lX). Refusing to load %s\n",
            (unsigned long)sig, dllPath);
        return 1;
    }
    printf("[L2WShell] Signature verified. Loading %s\n", dllPath);   /* llm generated */

    dll = LoadLibraryA(dllPath);   /* llm generated: was an inline literal; now uses dllPath */
    if (!dll) {
        fprintf(stderr, "Unable to load L2WShell.dll: %lu\n", GetLastError());
        return 1;
    }
    parse = (ParseCommandFn)GetProcAddress(dll, "ParseCommandExport");
    execute = (ExecuteCommandFn)GetProcAddress(dll, "ExecuteCommand"); //Name wrong
    if (!parse || !execute) {
        fprintf(stderr, "Missing required DLL export.\n");
        FreeLibrary(dll);
        return 1;
    }

    puts("L2WShell - Linux commands on Windows. Type help.");
    for (;;) {
        fputs("l2w> ", stdout);
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin))
            break;
        if (!strchr(line, '\n') && !feof(stdin)) {
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF) {}
            puts("Input too long.");
            continue;
        }
        argc = parse(line, args, MAX_ARGS);
        if (argc < 0) { puts("Malformed command."); continue; }
        if (dispatch(args, argc, execute) == -1)
            break;
        //remove execute = null
    }

    FreeLibrary(dll); //move free library to after loop
    return 0;
}
