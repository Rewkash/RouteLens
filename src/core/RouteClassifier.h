#pragma once

#include "core/Models.h"

namespace gpd::core {

class RouteClassifier final {
public:
    [[nodiscard]] static VerdictSummary classify(const QVector<ConnectionInfo>& connections);
    [[nodiscard]] static bool isPrivateAddress(const QString& ipAddress);
};

} // namespace gpd::core
