#include <Windows.h>
#include <iostream>
#include <string>
#include <wininet.h>
#include "libs/json.hpp"
#include <chrono>
#include <thread>
#include <vector>
#pragma comment(lib, "wininet.lib")

using namespace std;
using json = nlohmann::json;

string base64Decode(const string& encoded) {
    static const string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    string decoded;
    vector<int> decode_table(256, -1);
    for (int i = 0; i < 64; i++) decode_table[base64_chars[i]] = i;

    int val = 0, valb = -8;
    for (char c : encoded) {
        if (decode_table[c] == -1) break;
        val = (val << 6) + decode_table[c];
        valb += 6;
        if (valb >= 0) {
            decoded.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return decoded;
}

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

    string baseUrl = "aHR0cHM6Ly8zMDAwLWtydXNobmEwNi1saWNlbnNlbWFuYWdlLXBmZXBybGI1eTFrLndzLXVzMTE4LmdpdHBvZC5pby9hcGkvbGljZW5zZS8=";
    string decodedUrl = base64Decode(baseUrl) + licenseKey;

    wstring apiUrl(decodedUrl.begin(), decodedUrl.end());

    HINTERNET hInternet = pInternetOpen(L"LicenseValidator", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return false;

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
        cout << "[ >> ] If the issue persists, contact n0step_ on Discord." << endl;
        system("pause");
        return EXIT_FAILURE;
    }

    wchar_t* dllPath = argv[1];
    if (GetFileAttributes(dllPath) == INVALID_FILE_ATTRIBUTES) {
        cout << "[ FAILED ] DLL file does not exist." << endl;
        cout << "[ >> ] If the issue persists, contact n0step_ on Discord." << endl;
        system("pause");
        return EXIT_FAILURE;
    }

    HWND hwnd = FindWindowW(L"VALORANTUnrealWindow", NULL);
    if (hwnd == NULL) {
        cout << "[ FAILED ] Could not find target window." << endl;
        cout << "[ >> ] If the issue persists, contact n0step_ on Discord." << endl;
        system("pause");
        return EXIT_FAILURE;
    }

    DWORD pid = NULL;
    DWORD tid = GetWindowThreadProcessId(hwnd, &pid);
    if (tid == NULL) {
        cout << "[ FAILED ] Could not get thread ID of the target window." << endl;
        cout << "[ >> ] If the issue persists, contact n0step_ on Discord." << endl;
        system("pause");
        return EXIT_FAILURE;
    }

    cout << "[ OK ] Done. Press any key to exit." << endl;
    system("pause > nul");
    return EXIT_SUCCESS;
}
