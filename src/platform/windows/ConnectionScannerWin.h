#pragma once

#include "core/Models.h"

#include <QVector>

#include <QHash>

#include <cstdint>

namespace gpd::platform {

class ConnectionScannerWin final {
public:
    [[nodiscard]] QVector<gpd::core::ConnectionInfo> listConnectionsForPid(std::uint32_t pid) const;
    [[nodiscard]] QHash<std::uint32_t, int> activePidConnectionCounts() const;
};

} // namespace gpd::platform
