#include "core/PingScheduler.h"

#include "platform/windows/PingProbeWin.h"
#include "platform/windows/TcpPingProbeWin.h"
#include "platform/windows/UdpProbeWin.h"

#include <QDateTime>
#include <QHostAddress>
#include <QSet>
#include <QTimer>

namespace gpd::core {

PingScheduler::PingScheduler(gpd::platform::PingProbeWin* icmpProbe,
                             gpd::platform::TcpPingProbeWin* tcpProbe,
                             gpd::platform::UdpProbeWin* udpProbe,
                             QObject* parent)
    : QObject(parent)
    , tickTimer_(new QTimer(this))
    , icmpProbe_(icmpProbe)
    , tcpProbe_(tcpProbe)
    , udpProbe_(udpProbe) {
    tickTimer_->setInterval(500);
    connect(tickTimer_, &QTimer::timeout, this, &PingScheduler::onTick);
    connect(icmpProbe_, &gpd::platform::PingProbeWin::pingCompleted, this, &PingScheduler::onIcmpResult, Qt::QueuedConnection);
    connect(tcpProbe_, &gpd::platform::TcpPingProbeWin::pingCompleted, this, &PingScheduler::onTcpResult, Qt::QueuedConnection);
    connect(udpProbe_, &gpd::platform::UdpProbeWin::pingCompleted, this, &PingScheduler::onUdpResult, Qt::QueuedConnection);
}

void PingScheduler::updateTargets(const QVector<TargetEndpoint>& currentTargets) {
    updateTargetMap(targets_, currentTargets);
}

void PingScheduler::updateAnchorTargets(const QVector<TargetEndpoint>& anchorTargets) {
    updateTargetMap(anchorTargets_, anchorTargets);
}

void PingScheduler::updateTargetMap(QHash<QString, TargetState>& map, const QVector<TargetEndpoint>& endpoints) {
    QSet<QString> keep;
    for (const auto& target : endpoints) {
        if (target.ip.isEmpty() || target.isPrivate || shouldSkipTarget(target.ip)) {
            continue;
        }
        const QString key = makeTargetKey(target.ip, target.localAddress);
        keep.insert(key);
        auto& state = map[key];
        state.key = key;
        state.ip = target.ip;
        state.localAddress = target.localAddress;
        state.portForTcpFallback = target.port;
        state.preferTcp = target.preferTcp;
        state.preferUdp = target.preferUdp;
        state.udpPayload = target.udpPayload;
        if (state.preferTcp) {
            state.icmpBlocked = true;
        } else {
            state.icmpBlocked = false;
        }
    }
    for (auto it = map.begin(); it != map.end();) {
        if (!keep.contains(it.key())) {
            it = map.erase(it);
        } else {
            ++it;
        }
    }
}

void PingScheduler::start() {
    tickTimer_->start();
}

void PingScheduler::stop() {
    tickTimer_->stop();
}

QHash<QString, PingAggregate> PingScheduler::snapshot() const {
    return aggregator_.snapshot();
}

void PingScheduler::onTick() {
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    scheduleForMap(targets_, nowMs);
    scheduleForMap(anchorTargets_, nowMs);
}

void PingScheduler::scheduleForMap(QHash<QString, TargetState>& map, const std::int64_t nowMs) {
    for (auto it = map.begin(); it != map.end(); ++it) {
        if (pendingProbes_ >= 32) {
            break;
        }
        auto& state = it.value();
        if (state.lastProbeMs > 0 && nowMs - state.lastProbeMs < 250) {
            continue;
        }
        state.lastProbeMs = nowMs;
        ++pendingProbes_;
        if (state.preferUdp) {
            udpProbe_->enqueue(state.key, state.ip, state.portForTcpFallback, state.udpPayload, 1500, state.localAddress);
        } else if (state.preferTcp || state.icmpBlocked) {
            tcpProbe_->enqueue(state.key, state.ip, state.localAddress, state.portForTcpFallback == 0 ? 443 : state.portForTcpFallback, 700);
        } else {
            icmpProbe_->enqueue(state.key, state.ip, 500);
        }
    }
}

void PingScheduler::onIcmpResult(const QString& targetKey, const gpd::platform::PingResult& result) {
    pendingProbes_ = qMax(0, pendingProbes_ - 1);
    PingSample sample;
    sample.timedOut = result.timedOut;
    sample.rttMs = result.rttMs;
    sample.completedAtMs = result.completedAtMs;
    aggregator_.recordSample(targetKey, sample);
    aggregator_.recordUnreachable(targetKey, false);

    auto* state = findTargetState(targetKey);
    if (state == nullptr) {
        Q_EMIT aggregatesUpdated();
        return;
    }

    if (result.timedOut) {
        ++state->consecutiveTimeouts;
        if (state->consecutiveTimeouts >= 5) {
            state->icmpBlocked = true;
            aggregator_.recordIcmpBlocked(targetKey);
        }
    } else {
        state->consecutiveTimeouts = 0;
    }
    Q_EMIT aggregatesUpdated();
}

void PingScheduler::onTcpResult(const QString& targetKey, const gpd::platform::PingResult& result) {
    pendingProbes_ = qMax(0, pendingProbes_ - 1);
    PingSample sample;
    sample.timedOut = result.timedOut;
    sample.rttMs = result.rttMs;
    sample.completedAtMs = result.completedAtMs;
    aggregator_.recordSample(targetKey, sample);
    aggregator_.recordUnreachable(targetKey, result.timedOut);
    Q_EMIT aggregatesUpdated();
}

void PingScheduler::onUdpResult(const QString& targetKey, const gpd::platform::UdpProbeResult& result) {
    pendingProbes_ = qMax(0, pendingProbes_ - 1);
    PingSample sample;
    sample.timedOut = result.timedOut;
    sample.rttMs = result.rttMs;
    sample.completedAtMs = result.completedAtMs;
    aggregator_.recordSample(targetKey, sample);
    aggregator_.recordUnreachable(targetKey, result.timedOut);
    Q_EMIT aggregatesUpdated();
}

PingScheduler::TargetState* PingScheduler::findTargetState(const QString& targetKey) {
    auto it = targets_.find(targetKey);
    if (it != targets_.end()) {
        return &it.value();
    }
    auto ait = anchorTargets_.find(targetKey);
    if (ait != anchorTargets_.end()) {
        return &ait.value();
    }
    return nullptr;
}

QString PingScheduler::makeTargetKey(const QString& ip, const QString& localAddress) {
    return QStringLiteral("%1|%2").arg(ip, localAddress);
}

bool PingScheduler::shouldSkipTarget(const QString& ip) {
    const QHostAddress addr(ip);
    if (addr.isNull() || addr.isLoopback()) {
        return true;
    }
    if (addr.protocol() == QAbstractSocket::IPv4Protocol) {
        const quint32 value = addr.toIPv4Address();
        if ((value & 0xF0000000U) == 0xE0000000U) {
            return true;
        }
        if (value == 0xFFFFFFFFU) {
            return true;
        }
    }
    if (addr.protocol() == QAbstractSocket::IPv6Protocol && addr.isLinkLocal()) {
        return true;
    }
    return false;
}

} // namespace gpd::core
