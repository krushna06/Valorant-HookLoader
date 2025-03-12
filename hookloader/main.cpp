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

string WideStringToString(const wstring& wideStr) {
    if (wideStr.empty()) return string();
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), (int)wideStr.size(), nullptr, 0, nullptr, nullptr);
    string narrowStr(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), (int)wideStr.size(), &narrowStr[0], sizeNeeded, nullptr, nullptr);
    return narrowStr;
}

wstring StringToWideString(const string& narrowStr) {
    if (narrowStr.empty()) return wstring();
    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, narrowStr.c_str(), (int)narrowStr.size(), nullptr, 0);
    wstring wideStr(sizeNeeded, 0);
    MultiByteToWideChar(CP_UTF8, 0, narrowStr.c_str(), (int)narrowStr.size(), &wideStr[0], sizeNeeded);
    return wideStr;
}

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

typedef BOOL(WINAPI* tHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD);
tHttpSendRequest pHttpSendRequest;

typedef BOOL(WINAPI* tInternetWriteFile)(HINTERNET, LPCVOID, DWORD, LPDWORD);
tInternetWriteFile pInternetWriteFile;

string getHWID() {
    HW_PROFILE_INFO hwProfileInfo;
    if (!GetCurrentHwProfile(&hwProfileInfo)) {
        return "";
    }
    return WideStringToString(hwProfileInfo.szHwProfileGuid);
}

bool sendHWIDRequest(const string& licenseKey, const string& hwid) {
    HMODULE hWininet = LoadLibrary(L"wininet.dll");
    if (!hWininet) return false;

    pInternetOpen = (tInternetOpen)GetProcAddress(hWininet, "InternetOpenW");
    pInternetOpenUrl = (tInternetOpenUrl)GetProcAddress(hWininet, "InternetOpenUrlW");
    pInternetReadFile = (tInternetReadFile)GetProcAddress(hWininet, "InternetReadFile");
    pInternetCloseHandle = (tInternetCloseHandle)GetProcAddress(hWininet, "InternetCloseHandle");
    pHttpSendRequest = (tHttpSendRequest)GetProcAddress(hWininet, "HttpSendRequestW");
    pInternetWriteFile = (tInternetWriteFile)GetProcAddress(hWininet, "InternetWriteFile");

    string apiUrl = base64Decode("aHR0cHM6Ly9saWNlbnNlLW1hbmFnZXIubjBzdGVwLnh5ei9hcGkvaHdpZA==");
    wstring wideApiUrl = StringToWideString(apiUrl);

    HINTERNET hInternet = pInternetOpen(L"HWIDValidator", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return false;

    wstring domain = StringToWideString(base64Decode("bGljZW5zZS1tYW5hZ2VyLm4wc3RlcC54eXo="));
    HINTERNET hConnect = InternetConnect(hInternet, domain.c_str(), INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        pInternetCloseHandle(hInternet);
        return false;
    }

    HINTERNET hRequest = HttpOpenRequest(hConnect, L"POST", L"/api/hwid", NULL, NULL, NULL, INTERNET_FLAG_SECURE, 0);
    if (!hRequest) {
        pInternetCloseHandle(hConnect);
        pInternetCloseHandle(hInternet);
        return false;
    }

    json jsonData;
    jsonData["licenseId"] = licenseKey;
    jsonData["hwid"] = hwid;
    string jsonString = jsonData.dump();

    string headers = "Content-Type: application/json\r\n";
    wstring wideHeaders = StringToWideString(headers);

    if (!HttpAddRequestHeaders(hRequest, wideHeaders.c_str(), (DWORD)wideHeaders.length(), HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE)) {
        pInternetCloseHandle(hRequest);
        pInternetCloseHandle(hConnect);
        pInternetCloseHandle(hInternet);
        return false;
    }

    if (!HttpSendRequest(hRequest, NULL, 0, (LPVOID)jsonString.c_str(), (DWORD)jsonString.length())) {
        pInternetCloseHandle(hRequest);
        pInternetCloseHandle(hConnect);
        pInternetCloseHandle(hInternet);
        return false;
    }

    char buffer[1024];
    DWORD bytesRead;
    string response;

    while (pInternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead) {
        buffer[bytesRead] = 0;
        response += buffer;
    }

    pInternetCloseHandle(hRequest);
    pInternetCloseHandle(hConnect);
    pInternetCloseHandle(hInternet);

    try {
        json jsonResponse = json::parse(response, nullptr, false);
        if (!jsonResponse.is_discarded()) {
            if (jsonResponse["status"] == "success") {
                return true;
            }
            else if (jsonResponse["message"] == "Not the same pc") {
                cout << "[ FAILED ] Not the same PC. Please contact n0step_ on Discord." << endl;
                return false;
            }
        }
    }
    catch (const json::exception& e) {
        cout << "[ FAILED ] Failed to parse server response." << endl;
    }

    return false;
}

bool validateLicense(const string& licenseKey) {
    HMODULE hWininet = LoadLibrary(L"wininet.dll");
    if (!hWininet) return false;

    pInternetOpen = (tInternetOpen)GetProcAddress(hWininet, "InternetOpenW");
    pInternetOpenUrl = (tInternetOpenUrl)GetProcAddress(hWininet, "InternetOpenUrlW");
    pInternetReadFile = (tInternetReadFile)GetProcAddress(hWininet, "InternetReadFile");
    pInternetCloseHandle = (tInternetCloseHandle)GetProcAddress(hWininet, "InternetCloseHandle");

    string base64Url = "aHR0cHM6Ly9saWNlbnNlLW1hbmFnZXIubjBzdGVwLnh5ei9hcGkvbGljZW5zZS8=";
    string baseUrl = base64Decode(base64Url);
    string fullUrl = baseUrl + licenseKey;

    wstring wideFullUrl = StringToWideString(fullUrl);

    HINTERNET hInternet = pInternetOpen(L"LicenseValidator", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return false;

    HINTERNET hConnect = pInternetOpenUrl(hInternet, wideFullUrl.c_str(), NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE, 0);
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
    catch (const json::exception& e) {
        cout << "[ FAILED ] Failed to parse server response: " << e.what() << endl;
    }

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

    string hwid = getHWID();
    if (hwid.empty()) {
        cout << "[ FAILED ] Failed to retrieve HWID." << endl;
        cout << "[ >> ] If the issue persists, contact n0step_ on Discord." << endl;
        system("pause");
        return EXIT_FAILURE;
    }

    if (!sendHWIDRequest(licenseKey, hwid)) {
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
