#include "platform/windows/ProcessMonitorWin.h"

#include <qt_windows.h>

#include <tlhelp32.h>

#include <algorithm>

namespace gpd::platform {

QVector<gpd::core::ProcessInfo> ProcessMonitorWin::listProcesses() const {
    QVector<gpd::core::ProcessInfo> result;

    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return result;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(snapshot, &entry) == FALSE) {
        CloseHandle(snapshot);
        return result;
    }

    do {
        gpd::core::ProcessInfo process;
        process.pid = static_cast<std::uint32_t>(entry.th32ProcessID);
        process.name = QString::fromWCharArray(entry.szExeFile);
        result.push_back(process);
    } while (Process32NextW(snapshot, &entry) == TRUE);

    CloseHandle(snapshot);

    std::sort(result.begin(), result.end(), [](const gpd::core::ProcessInfo& lhs, const gpd::core::ProcessInfo& rhs) {
        if (lhs.name.compare(rhs.name, Qt::CaseInsensitive) == 0) {
            return lhs.pid < rhs.pid;
        }
        return lhs.name.compare(rhs.name, Qt::CaseInsensitive) < 0;
    });
    return result;
}

} // namespace gpd::platform
