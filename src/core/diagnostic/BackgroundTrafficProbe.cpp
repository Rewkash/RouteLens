#include "core/diagnostic/BackgroundTrafficProbe.h"

#include "core/UdpFlowAggregator.h"
#include "core/TunnelProcessRegistry.h"
#include "platform/windows/ProcessMonitorWin.h"

#include <algorithm>

namespace gpd::core {

BackgroundTrafficProbe::BackgroundTrafficProbe(const UdpFlowAggregator* udpFlows)
    : udpFlows_(udpFlows) {
}

void BackgroundTrafficProbe::setTargetPid(const std::uint32_t pid) {
    targetPid_ = pid;
}

void BackgroundTrafficProbe::setTunnelProcessRegistry(const TunnelProcessRegistry* registry) {
    tunnelRegistry_ = registry;
}

QString BackgroundTrafficProbe::probeId() const {
    return QStringLiteral("background_traffic");
}

bool BackgroundTrafficProbe::start() {
    return true;
}

void BackgroundTrafficProbe::stop() {
}

QVariantMap BackgroundTrafficProbe::snapshot() const {
    QVariantMap out;
    if (udpFlows_ == nullptr) {
        return out;
    }
    const auto byPid = udpFlows_->bandwidthBytesByPid(30000);
    struct Row {
        std::uint32_t pid;
        double mbps;
    };
    QVector<Row> rows;
    double totalBackgroundMbps = 0.0;
    double targetMbps = 0.0;
    double tunnelMbps = 0.0;
    QVariantList tunnelProcesses;
    for (auto it = byPid.cbegin(); it != byPid.cend(); ++it) {
        const double mbps = (static_cast<double>(it.value()) * 8.0) / (30.0 * 1000.0 * 1000.0);
        const QString processName = processNameForPid(it.key());
        const bool isTunnel = TunnelProcessRegistry::isKnownTunnel(processName);
        if (it.key() == targetPid_) {
            targetMbps += mbps;
        } else if (isTunnel) {
            tunnelMbps += mbps;
            QVariantMap tp;
            tp.insert(QStringLiteral("process"), processName);
            tp.insert(QStringLiteral("pid"), static_cast<qulonglong>(it.key()));
            tp.insert(QStringLiteral("bandwidthMbps"), mbps);
            tunnelProcesses.push_back(tp);
        } else {
            totalBackgroundMbps += mbps;
            rows.push_back({it.key(), mbps});
        }
    }
    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) { return a.mbps > b.mbps; });
    QVariantList talkers;
    for (int i = 0; i < rows.size() && i < 3; ++i) {
        QVariantMap t;
        t.insert(QStringLiteral("process"), processNameForPid(rows[i].pid));
        t.insert(QStringLiteral("pid"), static_cast<qulonglong>(rows[i].pid));
        t.insert(QStringLiteral("bandwidthMbps"), rows[i].mbps);
        talkers.push_back(t);
    }

    out.insert(QStringLiteral("topTalkers"), talkers);
    out.insert(QStringLiteral("totalBackgroundMbps"), totalBackgroundMbps);
    out.insert(QStringLiteral("targetProcessMbps"), targetMbps);
    out.insert(QStringLiteral("tunnelMbps"), tunnelMbps);
    out.insert(QStringLiteral("tunnelProcesses"), tunnelProcesses);
    out.insert(QStringLiteral("warningThresholdMbps"), 20.0);
    return out;
}

QString BackgroundTrafficProbe::processNameForPid(const std::uint32_t pid) const {
    gpd::platform::ProcessMonitorWin monitor;
    const auto processes = monitor.listProcesses();
    for (const auto& p : processes) {
        if (p.pid == pid) {
            return p.name;
        }
    }
    return QStringLiteral("pid:%1").arg(pid);
}

} // namespace gpd::core
