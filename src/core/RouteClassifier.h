#pragma once

#include "core/Models.h"

namespace gpd::core {

class TunnelCorrelator;

class RouteClassifier final {
public:
    [[nodiscard]] static VerdictSummary classify(const QVector<ConnectionInfo>& connections,
                                                 const TunnelCorrelator& correlator,
                                                 std::int64_t nowMs);
    [[nodiscard]] static bool isPrivateAddress(const QString& ipAddress);
};

} // namespace gpd::core
