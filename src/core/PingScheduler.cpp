#include "core/PingScheduler.h"

#include "platform/windows/PingProbeWin.h"
#include "platform/windows/TcpPingProbeWin.h"

#include <QDateTime>
#include <QHostAddress>
#include <QSet>
#include <QTimer>

namespace gpd::core {

PingScheduler::PingScheduler(gpd::platform::PingProbeWin* icmpProbe, gpd::platform::TcpPingProbeWin* tcpProbe, QObject* parent)
    : QObject(parent)
    , tickTimer_(new QTimer(this))
    , icmpProbe_(icmpProbe)
    , tcpProbe_(tcpProbe) {
    tickTimer_->setInterval(500);
    connect(tickTimer_, &QTimer::timeout, this, &PingScheduler::onTick);
    connect(icmpProbe_, &gpd::platform::PingProbeWin::pingCompleted, this, &PingScheduler::onIcmpResult, Qt::QueuedConnection);
    connect(tcpProbe_, &gpd::platform::TcpPingProbeWin::pingCompleted, this, &PingScheduler::onTcpResult, Qt::QueuedConnection);
}

void PingScheduler::updateTargets(const QVector<TargetEndpoint>& currentTargets) {
    QSet<QString> keep;
    for (const auto& target : currentTargets) {
        if (target.ip.isEmpty() || target.isPrivate || shouldSkipTarget(target.ip)) {
            continue;
        }
        keep.insert(target.ip);
        auto& state = targets_[target.ip];
        state.ip = target.ip;
        state.portForTcpFallback = target.port;
    }
    for (auto it = targets_.begin(); it != targets_.end();) {
        if (!keep.contains(it.key())) {
            it = targets_.erase(it);
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
    for (auto it = targets_.begin(); it != targets_.end(); ++it) {
        if (pendingProbes_ >= 32) {
            break;
        }
        auto& state = it.value();
        if (state.lastProbeMs > 0 && nowMs - state.lastProbeMs < 1000) {
            continue;
        }
        state.lastProbeMs = nowMs;
        ++pendingProbes_;
        if (state.icmpBlocked) {
            tcpProbe_->enqueue(state.ip, state.portForTcpFallback == 0 ? 443 : state.portForTcpFallback, 1500);
        } else {
            icmpProbe_->enqueue(state.ip, 1000);
        }
    }
}

void PingScheduler::onIcmpResult(const QString& ip, const gpd::platform::PingResult& result) {
    pendingProbes_ = qMax(0, pendingProbes_ - 1);
    PingSample sample;
    sample.timedOut = result.timedOut;
    sample.rttMs = result.rttMs;
    sample.completedAtMs = result.completedAtMs;
    aggregator_.recordSample(ip, sample);
    aggregator_.recordUnreachable(ip, false);

    auto it = targets_.find(ip);
    if (it == targets_.end()) {
        Q_EMIT aggregatesUpdated();
        return;
    }

    if (result.timedOut) {
        ++it->consecutiveTimeouts;
        if (it->consecutiveTimeouts >= 5) {
            it->icmpBlocked = true;
            aggregator_.recordIcmpBlocked(ip);
        }
    } else {
        it->consecutiveTimeouts = 0;
    }
    Q_EMIT aggregatesUpdated();
}

void PingScheduler::onTcpResult(const QString& ip, const gpd::platform::PingResult& result) {
    pendingProbes_ = qMax(0, pendingProbes_ - 1);
    PingSample sample;
    sample.timedOut = result.timedOut;
    sample.rttMs = result.rttMs;
    sample.completedAtMs = result.completedAtMs;
    aggregator_.recordSample(ip, sample);
    aggregator_.recordUnreachable(ip, result.timedOut);
    Q_EMIT aggregatesUpdated();
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
