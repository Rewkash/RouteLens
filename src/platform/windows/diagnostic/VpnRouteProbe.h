#pragma once

#include "core/diagnostic/IDiagnosticProbe.h"

namespace gpd::platform {

class VpnRouteProbe final : public gpd::core::IDiagnosticProbe {
public:
    [[nodiscard]] QString probeId() const override;
    bool start() override;
    void stop() override;
    [[nodiscard]] QVariantMap snapshot() const override;
};

} // namespace gpd::platform
