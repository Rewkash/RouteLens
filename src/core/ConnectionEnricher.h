#pragma once

#include "core/Models.h"

#include <QHash>
#include <QVector>

namespace gpd::platform {
class RouteResolverWin;
}

namespace gpd::core {

class ConnectionEnricher final {
public:
    [[nodiscard]] static QVector<ConnectionInfo> enrich(const QVector<ConnectionInfo>& connections,
                                                        const QHash<std::uint32_t, NetworkInterfaceInfo>& interfacesByIndex,
                                                        const gpd::platform::RouteResolverWin& resolver);
};

} // namespace gpd::core
