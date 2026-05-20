#pragma once

#include <QHash>
#include <QMutex>
#include <QString>
#include <QVector>

#include <cstdint>

#include "core/Models.h"

namespace gpd::core {

struct PingSample {
    bool timedOut{true};
    int rttMs{-1};
    std::int64_t completedAtMs{0};
};

class PingAggregator final {
public:
    void recordSample(const QString& ip, const PingSample& sample);
    void recordIcmpBlocked(const QString& ip);
    void recordUnreachable(const QString& ip, bool unreachable);
    [[nodiscard]] PingAggregate aggregateFor(const QString& ip) const;
    [[nodiscard]] QHash<QString, PingAggregate> snapshot() const;
    void prune(std::int64_t cutoffMs);

private:
    struct WindowState {
        QVector<int> recentRttMs;
        QVector<std::int64_t> recentTimestampsMs;
        double smoothedJitterMs{0.0};
        int lastRttMs{-1};
        int totalSamples{0};
        bool icmpBlocked{false};
        bool unreachable{false};
        std::int64_t lastSampleAtMs{0};
    };

    mutable QMutex mutex_;
    QHash<QString, WindowState> states_;
};

} // namespace gpd::core
