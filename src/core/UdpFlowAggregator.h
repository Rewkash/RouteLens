#pragma once

#include "core/Models.h"

#include <QHash>
#include <QMutex>
#include <QObject>
#include <QVector>

namespace gpd::core {

class UdpFlowAggregator final : public QObject {
    Q_OBJECT

public:
    explicit UdpFlowAggregator(QObject* parent = nullptr);

    void ingestBatch(const QVector<UdpFlowEvent>& events);
    [[nodiscard]] QVector<UdpEndpointObservation> endpointsFor(const UdpEndpointKey& key, std::int64_t freshnessMs = 30000) const;
    void pruneOlderThan(std::int64_t cutoffMs);

private:
    mutable QMutex mutex_;
    QHash<UdpEndpointKey, QVector<UdpEndpointObservation>> storage_;
};

} // namespace gpd::core
