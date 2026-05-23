#pragma once

#include "core/diagnostic/DiagnosticRuleEngine.h"
#include "core/diagnostic/DiagnosticTypes.h"

#include <QHash>
#include <QMutex>
#include <QObject>
#include <QVariantMap>

#include <memory>
#include <optional>

class QTimer;

namespace gpd::platform {
class HopProbe;
class PacketLossProbe;
}

namespace gpd::core {

class AnchorPingProbe;
class BackgroundTrafficProbe;
class BufferbloatProbe;
class PingScheduler;
class IDiagnosticProbe;
class UdpFlowAggregator;

class DiagnosticEngine final : public QObject {
    Q_OBJECT
public:
    explicit DiagnosticEngine(PingScheduler* pingScheduler, QObject* parent = nullptr);
    ~DiagnosticEngine() override;

    void setTarget(const QString& ip, int port, const QString& processName, const QString& localAddress = QString());
    void setConnectionContext(const ConnectionInfo& connectionInfo);
    void setTargetPid(std::uint32_t pid);
    void setUdpFlowAggregator(const UdpFlowAggregator* udpFlows);
    void clearConnectionContext();
    void startContinuous(int probeIntervalMs = 5000);
    void runFullDiagnostic();
    void stop();
    [[nodiscard]] DiagnosticReport currentReport() const;

Q_SIGNALS:
    void reportUpdated(const gpd::core::DiagnosticReport& report);
    void fullDiagnosticProgress(int percentDone, QString currentStep);
    void fullDiagnosticCompleted(const gpd::core::DiagnosticReport& report);

private:
    void collectAndPublish();

    std::unique_ptr<AnchorPingProbe> anchorProbe_;
    std::unique_ptr<BufferbloatProbe> bufferbloatProbe_;
    std::unique_ptr<BackgroundTrafficProbe> bgTrafficProbe_;
    std::unique_ptr<gpd::platform::HopProbe> hopProbe_;
    std::unique_ptr<gpd::platform::PacketLossProbe> lossProbe_;
    std::unique_ptr<IDiagnosticProbe> adapterProbe_;
    std::unique_ptr<IDiagnosticProbe> wifiProbe_;
    std::unique_ptr<IDiagnosticProbe> cpuProbe_;
    std::unique_ptr<IDiagnosticProbe> vpnRouteProbe_;
    DiagnosticRuleEngine ruleEngine_;
    QTimer* timer_{nullptr};
    QHash<QString, QVariantMap> snapshots_;
    DiagnosticReport report_;
    mutable QMutex reportMutex_;
    QString targetIp_;
    int targetPort_{0};
    QString processName_;
    QString targetLocalAddress_;
    std::optional<ConnectionInfo> contextConnection_;
    bool fullDiagnosticRunning_{false};
    bool fullHopDone_{false};
    bool fullBufferDone_{false};
    bool fullLossDone_{false};
};

} // namespace gpd::core
