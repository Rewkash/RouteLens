#include "core/diagnostic/BackgroundTrafficProbe.h"

#include "core/UdpFlowAggregator.h"
#include "platform/windows/ProcessMonitorWin.h"

#include <algorithm>

namespace gpd::core {

BackgroundTrafficProbe::BackgroundTrafficProbe(const UdpFlowAggregator* udpFlows)
    : udpFlows_(udpFlows) {
}

void BackgroundTrafficProbe::setTargetPid(const std::uint32_t pid) {
    targetPid_ = pid;
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
    for (auto it = byPid.cbegin(); it != byPid.cend(); ++it) {
        const double mbps = (static_cast<double>(it.value()) * 8.0) / (30.0 * 1000.0 * 1000.0);
        if (it.key() == targetPid_) {
            targetMbps += mbps;
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
