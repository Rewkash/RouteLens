#pragma once

#include "core/Models.h"

#include <optional>

namespace gpd::platform {

class RouteResolverWin final {
public:
    [[nodiscard]] std::optional<gpd::core::RoutingDecision> resolveRouteFor(const QString& remoteIp) const;
};

} // namespace gpd::platform
