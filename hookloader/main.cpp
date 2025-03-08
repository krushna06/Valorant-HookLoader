#include <Windows.h>
#include <iostream>
#include <string>
#include <wininet.h>
#include "libs/json.hpp"
#include <chrono>
#include <thread>
#pragma comment(lib, "wininet.lib")

using namespace std;
using json = nlohmann::json;

string decryptString(const string& encrypted) {
    string decrypted = encrypted;
    for (char& c : decrypted) c ^= 0x5A;
    return decrypted;
}

void antiDebug() {
    if (IsDebuggerPresent()) TerminateProcess(GetCurrentProcess(), 0);
    auto start = chrono::high_resolution_clock::now();
    this_thread::sleep_for(chrono::milliseconds(100));
    auto end = chrono::high_resolution_clock::now();
    if (chrono::duration_cast<chrono::milliseconds>(end - start).count() < 90) TerminateProcess(GetCurrentProcess(), 0);
}

typedef HINTERNET(WINAPI* tInternetOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
tInternetOpen pInternetOpen;

typedef HINTERNET(WINAPI* tInternetOpenUrl)(HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
tInternetOpenUrl pInternetOpenUrl;

typedef BOOL(WINAPI* tInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
tInternetReadFile pInternetReadFile;

typedef BOOL(WINAPI* tInternetCloseHandle)(HINTERNET);
tInternetCloseHandle pInternetCloseHandle;

bool validateLicense(const string& licenseKey) {
    HMODULE hWininet = LoadLibrary(L"wininet.dll");
    if (!hWininet) return false;

    pInternetOpen = (tInternetOpen)GetProcAddress(hWininet, "InternetOpenW");
    pInternetOpenUrl = (tInternetOpenUrl)GetProcAddress(hWininet, "InternetOpenUrlW");
    pInternetReadFile = (tInternetReadFile)GetProcAddress(hWininet, "InternetReadFile");
    pInternetCloseHandle = (tInternetCloseHandle)GetProcAddress(hWininet, "InternetCloseHandle");

    HINTERNET hInternet = pInternetOpen(L"LicenseValidator", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return false;

    wstring apiUrl = L"https://3000-krushna06-licensemanage-pfeprlb5y1k.ws-us118.gitpod.io/api/license/" + wstring(licenseKey.begin(), licenseKey.end());

    const wchar_t* headers = L"Content-Type: application/json\r\n";
    HINTERNET hConnect = pInternetOpenUrl(hInternet, apiUrl.c_str(), headers, -1, INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE, 0);
    if (!hConnect) {
        pInternetCloseHandle(hInternet);
        return false;
    }

    char buffer[1024];
    DWORD bytesRead;
    string response;

    while (pInternetReadFile(hConnect, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead) {
        buffer[bytesRead] = 0;
        response += buffer;
    }

    pInternetCloseHandle(hConnect);
    pInternetCloseHandle(hInternet);

    try {
        json jsonData = json::parse(response, nullptr, false);
        if (!jsonData.is_discarded() && jsonData["status"] == "success" && jsonData["license"]["status"] == "active") {
            return true;
        }
    }
    catch (const json::exception& e) {}

    return false;
}

int wmain(int argc, wchar_t* argv[], wchar_t* envp[]) {
    antiDebug();

    string licenseKey;
    cout << "Enter your license key: ";
    cin >> licenseKey;

    if (!validateLicense(licenseKey)) {
        cout << "[ FAILED ] Invalid or inactive license key." << endl;
        system("pause");
        return EXIT_FAILURE;
    }

    wchar_t* dllPath = argv[1];
    if (GetFileAttributes(dllPath) == INVALID_FILE_ATTRIBUTES) {
        cout << "[ FAILED ] DLL file does not exist." << endl;
        system("pause");
        return EXIT_FAILURE;
    }

    HWND hwnd = FindWindowW(L"VALORANTUnrealWindow", NULL);
    if (hwnd == NULL) {
        cout << "[ FAILED ] Could not find target window." << endl;
        system("pause");
        return EXIT_FAILURE;
    }

    DWORD pid = NULL;
    DWORD tid = GetWindowThreadProcessId(hwnd, &pid);
    if (tid == NULL) {
        cout << "[ FAILED ] Could not get thread ID of the target window." << endl;
        system("pause");
        return EXIT_FAILURE;
    }

    HMODULE dll = LoadLibraryEx(dllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (dll == NULL) {
        cout << "[ FAILED ] The DLL could not be found." << endl;
        system("pause");
        return EXIT_FAILURE;
    }

    HOOKPROC addr = (HOOKPROC)GetProcAddress(dll, "NextHook");
    if (addr == NULL) {
        cout << "[ FAILED ] The function was not found." << endl;
        system("pause");
        return EXIT_FAILURE;
    }

    HHOOK handle = SetWindowsHookEx(WH_GETMESSAGE, addr, dll, tid);
    if (handle == NULL) {
        cout << "[ FAILED ] Couldn't set the hook with SetWindowsHookEx." << endl;
        system("pause");
        return EXIT_FAILURE;
    }

    PostThreadMessage(tid, WM_NULL, NULL, NULL);

    cout << "[ OK ] Hook set and triggered." << endl;
    system("pause > nul");

    BOOL unhook = UnhookWindowsHookEx(handle);
    if (unhook == FALSE) {
        cout << "[ FAILED ] Could not remove the hook." << endl;
        system("pause");
        return EXIT_FAILURE;
    }

    cout << "[ OK ] Done. Press any key to exit." << endl;
    system("pause > nul");
    return EXIT_SUCCESS;
}
