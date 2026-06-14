// Программа демонстрирует набор распространённых антиотладочных и анти-VM техник для Windows. Она выполняет проверки наличия отладчика, анализирует родительский процесс, выявляет признаки виртуализации через CPUID и MAC-адреса, а также отслеживает аномалии, связанные с функцией Sleep. Результаты каждой проверки выводятся в консоль, позволяя оценить окружение, в котором выполняется процесс. Код может использоваться в исследовательских целях для изучения механизмов противодействия анализу и поведения программ в виртуальных средах.



#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <intrin.h>

#pragma comment(lib, "iphlpapi.lib")

BOOL check_is_debugger_present() {
    return IsDebuggerPresent();
}

BOOL check_remote_debugger_present() {
    BOOL debuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
    return debuggerPresent;
}

BOOL check_ntquery_debug_flags() {
    typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(
        HANDLE, UINT, PVOID, ULONG, PULONG);
    NTSTATUS status;
    ULONG noDebugInherit = 0;
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");

    status = NtQueryInformationProcess(GetCurrentProcess(), 0x1f, &noDebugInherit, sizeof(noDebugInherit), NULL);
    return noDebugInherit == 0;
}

BOOL check_startup_info() {
    STARTUPINFO si = { 0 };
    GetStartupInfo(&si);
    return (si.dwFlags & STARTF_USESHOWWINDOW);
}

BOOL check_process_parent() {
    DWORD pid = GetCurrentProcessId();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { .dwSize = sizeof(PROCESSENTRY32) };

    if (Process32First(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                HANDLE hParent = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ParentProcessID);
                if (hParent) {
                    TCHAR name[MAX_PATH] = { 0 };
                    GetModuleBaseName(hParent, NULL, name, MAX_PATH);
                    _wcslwr(name);
                    CloseHandle(hParent);

                    const wchar_t* suspects[] = {
                        L"x64dbg.exe", L"x32dbg.exe", L"ollydbg.exe", L"ida.exe", L"windbg.exe", L"code.exe"
                    };
                    for (int i = 0; i < sizeof(suspects) / sizeof(suspects[0]); i++) {
                        if (wcsstr(name, suspects[i]) != NULL) {
                            return TRUE;
                        }
                    }
                }
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return FALSE;
}

BOOL check_vm_cpuid() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] >> 31) & 1;
}

BOOL check_mac_vmware() {
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD buflen = sizeof(adapterInfo);
    DWORD status = GetAdaptersInfo(adapterInfo, &buflen);
    if (status != ERROR_SUCCESS) return FALSE;

    PIP_ADAPTER_INFO p = adapterInfo;
    while (p) {
        if (p->AddressLength == 6) {
            if ((p->Address[0] == 0x00 && p->Address[1] == 0x05 && p->Address[2] == 0x69) ||
                (p->Address[0] == 0x00 && p->Address[1] == 0x0C && p->Address[2] == 0x29) ||
                (p->Address[0] == 0x00 && p->Address[1] == 0x50 && p->Address[2] == 0x56)) {
                return TRUE;
            }
        }
        p = p->Next;
    }
    return FALSE;
}

BOOL check_sleep_skip() {
    DWORD t1 = GetTickCount();
    Sleep(2000);
    DWORD t2 = GetTickCount();
    return (t2 - t1) < 1500;
}

int main() {
    printf("[*] Запуск антиотладочных проверок...\n");

    if (check_is_debugger_present())
        printf("[!] IsDebuggerPresent: отладчик найден!\n");

    if (check_remote_debugger_present())
        printf("[!] CheckRemoteDebuggerPresent: отладчик найден!\n");

    if (check_ntquery_debug_flags())
        printf("[!] NtQueryInformationProcess: отладчик найден!\n");

    if (check_startup_info())
        printf("[!] StartupInfo: подозрение на запуск из среды\n");

    if (check_process_parent())
        printf("[!] Подозрительный родительский процесс!\n");

    if (check_vm_cpuid())
        printf("[!] Обнаружен гипервизор через CPUID!\n");

    if (check_mac_vmware())
        printf("[!] MAC-адрес указывает на виртуальную машину!\n");

    if (check_sleep_skip())
        printf("[!] Подозрительное поведение sleep — возможна отладка!\n");

    printf("\n[+] Проверка завершена.\n");
    return 0;
}
