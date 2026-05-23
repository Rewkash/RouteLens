#pragma once

#include "core/Models.h"
#include "core/PingAggregator.h"

#include <QHash>
#include <QObject>

#include <cstdint>

class QTimer;

namespace gpd::platform {
class PingProbeWin;
class TcpPingProbeWin;
struct PingResult;
}

namespace gpd::core {

struct TargetEndpoint {
    QString ip;
    QString localAddress;
    std::uint16_t port{0};
    bool isPrivate{false};
    bool preferTcp{false};
};

class PingScheduler final : public QObject {
    Q_OBJECT
public:
    PingScheduler(gpd::platform::PingProbeWin* icmpProbe, gpd::platform::TcpPingProbeWin* tcpProbe, QObject* parent = nullptr);

    void updateTargets(const QVector<TargetEndpoint>& currentTargets);
    void start();
    void stop();

    [[nodiscard]] QHash<QString, PingAggregate> snapshot() const;

Q_SIGNALS:
    void aggregatesUpdated();

private:
    struct TargetState {
        QString key;
        QString ip;
        QString localAddress;
        std::uint16_t portForTcpFallback{0};
        bool preferTcp{false};
        int consecutiveTimeouts{0};
        bool icmpBlocked{false};
        std::int64_t lastProbeMs{0};
    };

    void onTick();
    void onIcmpResult(const QString& targetKey, const gpd::platform::PingResult& result);
    void onTcpResult(const QString& targetKey, const gpd::platform::PingResult& result);
    static bool shouldSkipTarget(const QString& ip);
    static QString makeTargetKey(const QString& ip, const QString& localAddress);

    QTimer* tickTimer_{nullptr};
    QHash<QString, TargetState> targets_;
    PingAggregator aggregator_;
    gpd::platform::PingProbeWin* icmpProbe_{nullptr};
    gpd::platform::TcpPingProbeWin* tcpProbe_{nullptr};
    int pendingProbes_{0};
};

} // namespace gpd::core
