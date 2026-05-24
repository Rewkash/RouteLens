#pragma once

#include "core/diagnostic/IDiagnosticProbe.h"

#include <QHash>

namespace gpd::core {

class PingScheduler;

class AnchorPingProbe final : public IDiagnosticProbe {
public:
    explicit AnchorPingProbe(PingScheduler* scheduler);

    void setTarget(const QString& ip, int port, const QString& localAddress);
    [[nodiscard]] QString probeId() const override;
    bool start() override;
    void stop() override;
    [[nodiscard]] QVariantMap snapshot() const override;

private:
    PingScheduler* scheduler_{nullptr};
    QString targetIp_;
    int targetPort_{0};
    QString targetLocalAddress_;
    QString physicalLocalIp_;
};

} // namespace gpd::core
