#include "core/diagnostic/AnchorPingProbe.h"

#include "core/PingScheduler.h"
#include "platform/windows/RouteHelpersWin.h"
#include "platform/windows/UdpProbeWin.h"

namespace gpd::core {

namespace {

QVariantMap toMap(const PingAggregate& agg) {
    QVariantMap out;
    out.insert(QStringLiteral("rttMs"), agg.rttAvgMs);
    out.insert(QStringLiteral("jitterMs"), agg.jitterMs);
    out.insert(QStringLiteral("lossPercent"), agg.lossPercent);
    out.insert(QStringLiteral("samples"), agg.samplesInWindow);
    return out;
}

QString keyFor(const QString& ip, const QString& localAddress) {
    return QStringLiteral("%1|%2").arg(ip, localAddress);
}

} // namespace

AnchorPingProbe::AnchorPingProbe(PingScheduler* scheduler)
    : scheduler_(scheduler) {
}

void AnchorPingProbe::setTarget(const QString& ip, const int port, const QString& localAddress) {
    targetIp_ = ip;
    targetPort_ = port;
    targetLocalAddress_ = localAddress;
}

QString AnchorPingProbe::probeId() const {
    return QStringLiteral("anchor_ping");
}

bool AnchorPingProbe::start() {
    if (scheduler_ == nullptr) {
        return false;
    }
    QVector<TargetEndpoint> targets;
    const QString gatewayIp = gpd::platform::findPhysicalDefaultGateway();
    if (!gatewayIp.isEmpty()) {
        targets.push_back({gatewayIp, QString(), 0, false, false, false, gpd::platform::UdpProbePayload::Auto});
    }
    targets.push_back({QStringLiteral("1.1.1.1"), QString(), 53, false, false, true, gpd::platform::UdpProbePayload::DnsQuery});
    targets.push_back({QStringLiteral("8.8.8.8"), QString(), 53, false, false, true, gpd::platform::UdpProbePayload::DnsQuery});
    targets.push_back({QStringLiteral("9.9.9.9"), QString(), 53, false, false, true, gpd::platform::UdpProbePayload::DnsQuery});
    targets.push_back({QStringLiteral("1.0.0.1"), QString(), 53, false, false, true, gpd::platform::UdpProbePayload::DnsQuery});
    if (!targetIp_.isEmpty()) {
        targets.push_back({targetIp_, targetLocalAddress_, static_cast<std::uint16_t>(targetPort_), false, false, true,
                           gpd::platform::UdpProbePayload::SourceA2sInfo});
        targets.push_back({targetIp_, QString(), 1, false, false, true, gpd::platform::UdpProbePayload::ClosedPortProbe});
    }
    scheduler_->updateAnchorTargets(targets);
    return true;
}

void AnchorPingProbe::stop() {
}

QVariantMap AnchorPingProbe::snapshot() const {
    QVariantMap out;
    if (scheduler_ == nullptr) {
        return out;
    }
    const auto snap = scheduler_->snapshot();
    out.insert(QStringLiteral("anchor_1_1_1_1"), toMap(snap.value(keyFor(QStringLiteral("1.1.1.1"), QString()))));
    out.insert(QStringLiteral("anchor_8_8_8_8"), toMap(snap.value(keyFor(QStringLiteral("8.8.8.8"), QString()))));
    out.insert(QStringLiteral("anchor_9_9_9_9"), toMap(snap.value(keyFor(QStringLiteral("9.9.9.9"), QString()))));
    out.insert(QStringLiteral("anchor_1_0_0_1"), toMap(snap.value(keyFor(QStringLiteral("1.0.0.1"), QString()))));
    const QString gatewayIp = gpd::platform::findPhysicalDefaultGateway();
    if (!gatewayIp.isEmpty()) {
        out.insert(QStringLiteral("gateway"), toMap(snap.value(keyFor(gatewayIp, QString()))));
        out.insert(QStringLiteral("gatewayIp"), gatewayIp);
    }
    if (!targetIp_.isEmpty()) {
        out.insert(QStringLiteral("target"), toMap(snap.value(keyFor(targetIp_, targetLocalAddress_))));
        out.insert(QStringLiteral("target_path_loss"), toMap(snap.value(keyFor(targetIp_, QString()))));
    }
    return out;
}

} // namespace gpd::core
