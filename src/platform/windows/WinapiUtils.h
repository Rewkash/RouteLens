#pragma once

#include <QString>

namespace gpd::platform {

[[nodiscard]] bool isRunningAsAdministrator();
[[nodiscard]] QString lastWindowsErrorToString(unsigned long errorCode);

} // namespace gpd::platform
