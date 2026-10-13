#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

#define LOG_PATH "C:\\Temp\\dllrunner_log.txt"

static void LogResult(const char* funcName, const char* fmt, ...)
{
    FILE* f = NULL;
    if (fopen_s(&f, LOG_PATH, "a") != 0 || !f) return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f, "[%02d:%02d:%02d.%03d] %-8s => ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, funcName);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

#define RUNDLL_FUNC(name) \
    void CALLBACK name(HWND hWnd, HINSTANCE hInst, LPSTR lpszCmdLine, int nCmdShow)

#define UNUSED_PARAMS (void)hWnd; (void)hInst; (void)lpszCmdLine; (void)nCmdShow;


RUNDLL_FUNC(Func01) { UNUSED_PARAMS
    LogResult("Func01", "Hello from function 01");
}

RUNDLL_FUNC(Func02) { UNUSED_PARAMS
    LogResult("Func02", "Current PID = %lu", GetCurrentProcessId());
}

RUNDLL_FUNC(Func03) { UNUSED_PARAMS
    SYSTEMTIME st; GetLocalTime(&st);
    LogResult("Func03", "Local time = %04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

RUNDLL_FUNC(Func04) { UNUSED_PARAMS
    char buf[256] = {0}; DWORD sz = sizeof(buf);
    GetComputerNameA(buf, &sz);
    LogResult("Func04", "Computer name = %s", buf);
}

RUNDLL_FUNC(Func05) { UNUSED_PARAMS
    char buf[256] = {0}; DWORD sz = sizeof(buf);
    GetUserNameA(buf, &sz);
    LogResult("Func05", "User name = %s", buf);
}

RUNDLL_FUNC(Func06) { UNUSED_PARAMS
    char buf[MAX_PATH] = {0};
    GetWindowsDirectoryA(buf, MAX_PATH);
    LogResult("Func06", "Windows dir = %s", buf);
}

RUNDLL_FUNC(Func07) { UNUSED_PARAMS
    LogResult("Func07", "About to show BLOCKING MessageBox...");
    MessageBoxA(NULL, "Func07 blocks. Click OK to continue.", "Blocking",
                MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL);
    LogResult("Func07", "MessageBox closed by user");
}

RUNDLL_FUNC(Func08) { UNUSED_PARAMS
    ULARGE_INTEGER freeBytes, totalBytes, totalFree;
    if (GetDiskFreeSpaceExA("C:\\", &freeBytes, &totalBytes, &totalFree)) {
        LogResult("Func08", "C: free = %llu MB / total = %llu MB",
            freeBytes.QuadPart / (1024*1024), totalBytes.QuadPart / (1024*1024));
    } else {
        LogResult("Func08", "GetDiskFreeSpaceEx failed: %lu", GetLastError());
    }
}

RUNDLL_FUNC(Func09) { UNUSED_PARAMS
    ULONGLONG ms = GetTickCount64();
    LogResult("Func09", "Uptime = %llu s (~%llu h)", ms/1000, ms/1000/3600);
}

RUNDLL_FUNC(Func10) { UNUSED_PARAMS
    char buf[MAX_PATH] = {0};
    GetTempPathA(MAX_PATH, buf);
    LogResult("Func10", "Temp path = %s", buf);
}

RUNDLL_FUNC(Func11) { UNUSED_PARAMS
    LogResult("Func11", "About to crash deliberately...");
    volatile int* p = NULL;
    *p = 42;
    LogResult("Func11", "UNREACHABLE");
}

RUNDLL_FUNC(Func12) { UNUSED_PARAMS
    srand((unsigned)time(NULL) ^ GetCurrentProcessId());
    LogResult("Func12", "Random number = %d", rand());
}

RUNDLL_FUNC(Func13_Calc) { UNUSED_PARAMS
    LogResult("Func13_Calc", "Launching calc.exe ...");
    HINSTANCE r = ShellExecuteA(NULL, "open", "calc.exe", NULL, NULL, SW_SHOWNORMAL);
    if ((INT_PTR)r > 32)
        LogResult("Func13_Calc", "calc.exe launched OK");
    else
        LogResult("Func13_Calc", "ShellExecute failed, code=%lld", (long long)(INT_PTR)r);
}


RUNDLL_FUNC(Func14) { UNUSED_PARAMS
    OSVERSIONINFOA vi = {0}; vi.dwOSVersionInfoSize = sizeof(vi);
#pragma warning(suppress:4996)
    GetVersionExA(&vi);
    LogResult("Func14", "OS version = %lu.%lu build %lu",
        vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
}

RUNDLL_FUNC(Func15) { UNUSED_PARAMS
    SYSTEM_INFO si; GetSystemInfo(&si);
    LogResult("Func15", "Processors = %lu", si.dwNumberOfProcessors);
}

RUNDLL_FUNC(Func16) { UNUSED_PARAMS
    MEMORYSTATUSEX ms = {0}; ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    LogResult("Func16", "RAM: %llu%% used, %llu MB avail",
        ms.dwMemoryLoad, ms.ullAvailPhys / (1024*1024));
}

RUNDLL_FUNC(Func17) { UNUSED_PARAMS
    LogResult("Func17", "Sleeping 60s (BLOCKING)...");
    Sleep(60000);
    LogResult("Func17", "Woke up");
}

RUNDLL_FUNC(Func18) { UNUSED_PARAMS
    char buf[256] = {0}; DWORD n = GetEnvironmentVariableA("PATH", buf, sizeof(buf));
    LogResult("Func18", "PATH length = %lu, first 80 chars = %.80s", n, buf);
}

RUNDLL_FUNC(Func19) { UNUSED_PARAMS
    char buf[MAX_PATH] = {0};
    GetCurrentDirectoryA(MAX_PATH, buf);
    LogResult("Func19", "CWD = %s", buf);
}

RUNDLL_FUNC(Func20) { UNUSED_PARAMS
    LogResult("Func20", "Goodbye from function 20");
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL; (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
    }
    return TRUE;
}