#include <cstdio>
#include <Windows.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>
#include <vector>
#include <regex>
#include <set>

DWORD find_pid_by_name(const std::string &name) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    DWORD process_id = -1;
    if (Process32First(snapshot, &entry) == TRUE) {
        while (Process32Next(snapshot, &entry) == TRUE) {
            if (strcmp(name.c_str(), entry.szExeFile) == 0) {
                process_id = entry.th32ProcessID;
            }
        }
    }

    CloseHandle(snapshot);
    return process_id;
}

char *check_addr(const char *pattern, char *begin, SIZE_T size) {
    size_t pattern_len = strlen(pattern);

    for (int i = 0; i < size; i++) {
        bool found = true;

        for (int j = 0; j < pattern_len; j++) {
            if (pattern[j] != *(char *) ((intptr_t) begin + i + j)) {
                found = false;
                break;
            }
        }

        if (found) {
            return (begin + i);
        }
    }

    return nullptr;
}

std::vector<std::string> find_matches(const char *pattern, HANDLE process_handle) {
    MEMORY_BASIC_INFORMATION mbi;
    mbi.RegionSize = 0x10000;
    char *begin = nullptr;
    VirtualQueryEx(process_handle, (LPCVOID) begin, &mbi, sizeof(mbi));

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    char *buffer = nullptr;
    std::vector<std::string> potential_strings = {};
    for (char *curr = begin; curr < si.lpMaximumApplicationAddress; curr += mbi.RegionSize) {
        if (!VirtualQueryEx(process_handle, curr, &mbi, sizeof(mbi))) {
            continue;
        }

        if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS) {
            continue;
        }

        delete[] buffer;
        buffer = new char[mbi.RegionSize];

        SIZE_T bytes_read;
        ReadProcessMemory(process_handle, mbi.BaseAddress, buffer, mbi.RegionSize, &bytes_read);

        char *match = check_addr(pattern, buffer, bytes_read);
        if (match != nullptr) {
            potential_strings.emplace_back(match);
        }
    }

    delete[] buffer;
    return potential_strings;
}

int main() {
    // Summoner names with non-ASCII characters were rendered incorrectly
    // https://stackoverflow.com/q/45575863
    // Set console code page to UTF-8 so console known how to interpret string data
    SetConsoleOutputCP(CP_UTF8);
    // Enable buffering to prevent VS from chopping up UTF-8 byte sequences
    setvbuf(stdout, nullptr, _IOFBF, 1000);

    std::string PROCESS_NAME = "LeagueClient.exe";

    DWORD pid = find_pid_by_name(PROCESS_NAME);
    if (pid == -1) {
        std::cout << "Failed to find " << PROCESS_NAME << std::endl;
        return -1;
    }
    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

    // strings that begin with "{"participants":" tend to contain champ select summoner info
    // we iterate over memory finding all bytes that match these values
    std::vector<std::string> matches = find_matches("{\"participants\":", process_handle);

    std::set<std::string> names = {};
    // since found matches are not guaranteed to be valid json (they're usually incomplete),
    // we use simple regex to match "name" attributes.
    std::regex re("\"name\"\\s*:\\s*\"(.+?)\"");
    for (std::string &match: matches) {
        std::smatch sm;

        while (regex_search(match, sm, re)) {
            // insert first captured group
            names.insert(sm[1].str());
            match = sm.suffix();
        }
    }

    for (const std::string &name: names) {
        std::cout << name << std::endl;
    }

    system("pause");

    return 0;
}
