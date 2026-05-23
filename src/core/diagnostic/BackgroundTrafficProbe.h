#pragma once

#include "core/diagnostic/IDiagnosticProbe.h"

namespace gpd::core {

class UdpFlowAggregator;
class TunnelProcessRegistry;

class BackgroundTrafficProbe final : public IDiagnosticProbe {
public:
    explicit BackgroundTrafficProbe(const UdpFlowAggregator* udpFlows);

    void setTargetPid(std::uint32_t pid);
    void setTunnelProcessRegistry(const TunnelProcessRegistry* registry);

    [[nodiscard]] QString probeId() const override;
    bool start() override;
    void stop() override;
    [[nodiscard]] QVariantMap snapshot() const override;

private:
    QString processNameForPid(std::uint32_t pid) const;

    const UdpFlowAggregator* udpFlows_{nullptr};
    const TunnelProcessRegistry* tunnelRegistry_{nullptr};
    std::uint32_t targetPid_{0};
};

} // namespace gpd::core
