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
    targets.push_back({QStringLiteral("162.159.200.123"), QString(), 123, false, false, true, gpd::platform::UdpProbePayload::NtpQuery});
    targets.push_back({QStringLiteral("216.239.35.0"), QString(), 123, false, false, true, gpd::platform::UdpProbePayload::NtpQuery});
    targets.push_back({QStringLiteral("216.239.35.4"), QString(), 123, false, false, true, gpd::platform::UdpProbePayload::NtpQuery});
    targets.push_back({QStringLiteral("132.163.97.4"), QString(), 123, false, false, true, gpd::platform::UdpProbePayload::NtpQuery});
    if (!targetIp_.isEmpty()) {
        targets.push_back({targetIp_, targetLocalAddress_, static_cast<std::uint16_t>(targetPort_), false, false, true,
                           gpd::platform::UdpProbePayload::SourceA2sInfo});
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
    out.insert(QStringLiteral("anchor_cf_ntp"), toMap(snap.value(keyFor(QStringLiteral("162.159.200.123"), QString()))));
    out.insert(QStringLiteral("anchor_google_ntp_a"), toMap(snap.value(keyFor(QStringLiteral("216.239.35.0"), QString()))));
    out.insert(QStringLiteral("anchor_google_ntp_b"), toMap(snap.value(keyFor(QStringLiteral("216.239.35.4"), QString()))));
    out.insert(QStringLiteral("anchor_nist_ntp"), toMap(snap.value(keyFor(QStringLiteral("132.163.97.4"), QString()))));
    const QString gatewayIp = gpd::platform::findPhysicalDefaultGateway();
    if (!gatewayIp.isEmpty()) {
        out.insert(QStringLiteral("gateway"), toMap(snap.value(keyFor(gatewayIp, QString()))));
        out.insert(QStringLiteral("gatewayIp"), gatewayIp);
    }
    if (!targetIp_.isEmpty()) {
        out.insert(QStringLiteral("target"), toMap(snap.value(keyFor(targetIp_, targetLocalAddress_))));
    }
    return out;
}

} // namespace gpd::core
