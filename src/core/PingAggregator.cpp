#include "core/PingAggregator.h"

#include <QDateTime>

namespace {

constexpr int kMaxSamples = 60;
constexpr qint64 kWindowMs = 30000;

template <typename TState>
void pruneWindow(TState& state, const qint64 nowMs) {
    while (!state.recentTimestampsMs.isEmpty()) {
        const bool tooOld = nowMs - state.recentTimestampsMs.front() > kWindowMs;
        const bool tooMany = state.recentTimestampsMs.size() > kMaxSamples;
        if (!tooOld && !tooMany) {
            break;
        }
        state.recentTimestampsMs.removeFirst();
        state.recentRttMs.removeFirst();
    }
}

template <typename TState>
gpd::core::PingAggregate toAggregate(const TState& state) {
    gpd::core::PingAggregate out;
    out.icmpBlocked = state.icmpBlocked;
    out.unreachable = state.unreachable;
    out.totalSamples = state.totalSamples;
    out.samplesInWindow = state.recentRttMs.size();
    out.jitterMs = state.smoothedJitterMs;
    out.lastSampleAtMs = state.lastSampleAtMs;

    int okCount = 0;
    int sum = 0;
    int minRtt = -1;
    int maxRtt = -1;
    int lossCount = 0;
    for (const int rtt : state.recentRttMs) {
        if (rtt < 0) {
            ++lossCount;
            continue;
        }
        ++okCount;
        sum += rtt;
        minRtt = minRtt < 0 ? rtt : qMin(minRtt, rtt);
        maxRtt = maxRtt < 0 ? rtt : qMax(maxRtt, rtt);
    }
    out.rttMinMs = minRtt;
    out.rttMaxMs = maxRtt;
    out.rttAvgMs = okCount > 0 ? sum / okCount : -1;
    out.lossPercent = out.samplesInWindow > 0 ? (100.0 * static_cast<double>(lossCount) / static_cast<double>(out.samplesInWindow)) : 0.0;
    return out;
}

} // namespace

namespace gpd::core {

void PingAggregator::recordSample(const QString& ip, const PingSample& sample) {
    QMutexLocker lock(&mutex_);
    auto& state = states_[ip];
    const qint64 nowMs = sample.completedAtMs > 0 ? sample.completedAtMs : QDateTime::currentMSecsSinceEpoch();

    if (!sample.timedOut && sample.rttMs >= 0) {
        if (state.lastRttMs >= 0) {
            const double d = qAbs(sample.rttMs - state.lastRttMs);
            state.smoothedJitterMs += (d - state.smoothedJitterMs) / 16.0;
        }
        state.lastRttMs = sample.rttMs;
        state.unreachable = false;
    }

    state.recentRttMs.push_back(sample.timedOut ? -1 : sample.rttMs);
    state.recentTimestampsMs.push_back(nowMs);
    ++state.totalSamples;
    state.lastSampleAtMs = nowMs;
    pruneWindow(state, nowMs);
}

void PingAggregator::recordIcmpBlocked(const QString& ip) {
    QMutexLocker lock(&mutex_);
    states_[ip].icmpBlocked = true;
}

void PingAggregator::recordUnreachable(const QString& ip, const bool unreachable) {
    QMutexLocker lock(&mutex_);
    states_[ip].unreachable = unreachable;
}

PingAggregate PingAggregator::aggregateFor(const QString& ip) const {
    QMutexLocker lock(&mutex_);
    const auto it = states_.constFind(ip);
    if (it == states_.cend()) {
        return {};
    }
    return toAggregate(it.value());
}

QHash<QString, PingAggregate> PingAggregator::snapshot() const {
    QMutexLocker lock(&mutex_);
    QHash<QString, PingAggregate> out;
    out.reserve(states_.size());
    for (auto it = states_.cbegin(); it != states_.cend(); ++it) {
        out.insert(it.key(), toAggregate(it.value()));
    }
    return out;
}

void PingAggregator::prune(const std::int64_t cutoffMs) {
    QMutexLocker lock(&mutex_);
    for (auto it = states_.begin(); it != states_.end();) {
        pruneWindow(it.value(), cutoffMs);
        if (it.value().recentRttMs.isEmpty() && it.value().lastSampleAtMs < cutoffMs) {
            it = states_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace gpd::core
