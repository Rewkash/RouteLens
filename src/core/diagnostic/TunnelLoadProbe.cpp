#include "core/diagnostic/TunnelLoadProbe.h"

#include "platform/windows/RouteHelpersWin.h"

#include <QDateTime>

namespace gpd::core {

namespace {

constexpr int kMaxIntervalMs = 60000;

double rateBps(const quint64 prev, const quint64 cur, const qint64 dtMs) {
    if (dtMs <= 0 || dtMs > kMaxIntervalMs) {
        return 0.0;
    }
    if (cur < prev) {
        return 0.0;
    }
    const double delta = static_cast<double>(cur - prev);
    return delta * 1000.0 / static_cast<double>(dtMs);
}

double bpsToMbps(const double bytesPerSecond) {
    return bytesPerSecond * 8.0 / 1'000'000.0;
}

} // namespace

TunnelLoadProbe::TunnelLoadProbe() = default;

QString TunnelLoadProbe::probeId() const {
    return QStringLiteral("tunnel_load");
}

bool TunnelLoadProbe::start() {
    primed_ = false;
    lastSampleMs_ = 0;
    lastTunnelIn_ = 0;
    lastTunnelOut_ = 0;
    lastPhysicalIn_ = 0;
    lastPhysicalOut_ = 0;
    lastTunnelName_.clear();
    lastPhysicalName_.clear();
    return true;
}

void TunnelLoadProbe::stop() {
}

QVariantMap TunnelLoadProbe::snapshot() const {
    QVariantMap out;
    const auto tunnel = gpd::platform::aggregateTunnelStats();
    const auto physical = gpd::platform::aggregatePhysicalStats();
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();

    double tunnelInMbps = 0.0;
    double tunnelOutMbps = 0.0;
    double physicalInMbps = 0.0;
    double physicalOutMbps = 0.0;

    if (primed_) {
        const qint64 dtMs = nowMs - lastSampleMs_;
        tunnelInMbps = bpsToMbps(rateBps(lastTunnelIn_, tunnel.inOctets, dtMs));
        tunnelOutMbps = bpsToMbps(rateBps(lastTunnelOut_, tunnel.outOctets, dtMs));
        physicalInMbps = bpsToMbps(rateBps(lastPhysicalIn_, physical.inOctets, dtMs));
        physicalOutMbps = bpsToMbps(rateBps(lastPhysicalOut_, physical.outOctets, dtMs));
    }

    lastSampleMs_ = nowMs;
    lastTunnelIn_ = tunnel.inOctets;
    lastTunnelOut_ = tunnel.outOctets;
    lastPhysicalIn_ = physical.inOctets;
    lastPhysicalOut_ = physical.outOctets;
    lastTunnelName_ = tunnel.friendlyName;
    lastPhysicalName_ = physical.friendlyName;
    primed_ = true;

    out.insert(QStringLiteral("tunnelFound"), tunnel.found);
    out.insert(QStringLiteral("tunnelName"), tunnel.friendlyName);
    out.insert(QStringLiteral("tunnelInMbps"), tunnelInMbps);
    out.insert(QStringLiteral("tunnelOutMbps"), tunnelOutMbps);
    out.insert(QStringLiteral("physicalFound"), physical.found);
    out.insert(QStringLiteral("physicalName"), physical.friendlyName);
    out.insert(QStringLiteral("physicalInMbps"), physicalInMbps);
    out.insert(QStringLiteral("physicalOutMbps"), physicalOutMbps);
    out.insert(QStringLiteral("sampleTimestampMs"), nowMs);
    return out;
}

} // namespace gpd::core
