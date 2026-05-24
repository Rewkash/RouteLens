#pragma once

#include "core/diagnostic/IDiagnosticProbe.h"

#include <QString>
#include <QVariantMap>

#include <cstdint>

namespace gpd::core {

class TunnelLoadProbe final : public IDiagnosticProbe {
public:
    TunnelLoadProbe();

    [[nodiscard]] QString probeId() const override;
    bool start() override;
    void stop() override;
    [[nodiscard]] QVariantMap snapshot() const override;

private:
    mutable std::int64_t lastSampleMs_{0};
    mutable quint64 lastTunnelIn_{0};
    mutable quint64 lastTunnelOut_{0};
    mutable quint64 lastPhysicalIn_{0};
    mutable quint64 lastPhysicalOut_{0};
    mutable bool primed_{false};
    mutable QString lastTunnelName_;
    mutable QString lastPhysicalName_;
};

} // namespace gpd::core
