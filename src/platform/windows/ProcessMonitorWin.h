#pragma once

#include "core/Models.h"

#include <QVector>

namespace gpd::platform {

class ProcessMonitorWin final {
public:
    [[nodiscard]] QVector<gpd::core::ProcessInfo> listProcesses() const;
};

} // namespace gpd::platform
