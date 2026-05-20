#include "platform/windows/WinapiUtils.h"

#include <qt_windows.h>

namespace gpd::platform {

bool isRunningAsAdministrator() {
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;

    const auto sidCreated = AllocateAndInitializeSid(
        &ntAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0,
        0,
        0,
        0,
        0,
        0,
        &adminGroup);
    if (sidCreated == FALSE || adminGroup == nullptr) {
        return false;
    }

    BOOL isMember = FALSE;
    const auto checked = CheckTokenMembership(nullptr, adminGroup, &isMember);
    FreeSid(adminGroup);

    return checked == TRUE && isMember == TRUE;
}

QString lastWindowsErrorToString(const unsigned long errorCode) {
    wchar_t* buffer = nullptr;
    const auto size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);

    if (size == 0 || buffer == nullptr) {
        return QStringLiteral("Windows error %1").arg(errorCode);
    }

    const QString message = QString::fromWCharArray(buffer, static_cast<int>(size)).trimmed();
    LocalFree(buffer);
    return message;
}

} // namespace gpd::platform
