#include "core/UdpFlowAggregator.h"

#include <QDateTime>

namespace gpd::core {

UdpFlowAggregator::UdpFlowAggregator(QObject* parent)
    : QObject(parent) {}

void UdpFlowAggregator::ingestBatch(const QVector<UdpFlowEvent>& events) {
    QMutexLocker locker(&mutex_);
    if (storage_.size() > 10000) {
        return;
    }

    for (const auto& event : events) {
        if (event.protocol != TransportProtocol::Udp) {
            continue;
        }
        UdpEndpointKey key;
        key.pid = event.pid;
        key.localAddress = event.localAddress;
        key.localPort = event.localPort;
        const bool isAnyIPv4 = event.localAddress == QStringLiteral("0.0.0.0");
        const bool isAnyIPv6 = event.localAddress == QStringLiteral("::");

        const auto upsert = [&](const UdpEndpointKey& endpointKey) {
            auto& observations = storage_[endpointKey];
            int foundIndex = -1;
            for (int i = 0; i < observations.size(); ++i) {
                if (observations[i].remoteAddress == event.remoteAddress && observations[i].remotePort == event.remotePort) {
                    foundIndex = i;
                    break;
                }
            }

            if (foundIndex < 0) {
                if (observations.size() >= 64) {
                    int oldest = 0;
                    for (int i = 1; i < observations.size(); ++i) {
                        if (observations[i].lastSeenMs < observations[oldest].lastSeenMs) {
                            oldest = i;
                        }
                    }
                    observations.removeAt(oldest);
                }
                UdpEndpointObservation observation;
                observation.remoteAddress = event.remoteAddress;
                observation.remotePort = event.remotePort;
                observation.isIPv6 = event.isIPv6;
                observation.firstSeenMs = event.timestampMs;
                observation.lastSeenMs = event.timestampMs;
                observations.push_back(observation);
                foundIndex = observations.size() - 1;
            }

            auto& observation = observations[foundIndex];
            observation.lastSeenMs = event.timestampMs;
            if (event.isSend) {
                observation.sentPackets += 1;
                observation.sentBytes += event.sizeBytes;
            } else {
                observation.recvPackets += 1;
                observation.recvBytes += event.sizeBytes;
            }
        };

        upsert(key);
        if (!isAnyIPv4 && !isAnyIPv6) {
            UdpEndpointKey anyKey;
            anyKey.pid = event.pid;
            anyKey.localAddress = event.isIPv6 ? QStringLiteral("::") : QStringLiteral("0.0.0.0");
            anyKey.localPort = event.localPort;
            upsert(anyKey);
        }
    }
}

QVector<UdpEndpointObservation> UdpFlowAggregator::endpointsFor(const UdpEndpointKey& key, const std::int64_t freshnessMs) const {
    QVector<UdpEndpointObservation> result;
    QMutexLocker locker(&mutex_);
    const auto it = storage_.constFind(key);
    if (it == storage_.cend()) {
        return result;
    }

    const auto now = QDateTime::currentMSecsSinceEpoch();
    for (const auto& observation : it.value()) {
        if (observation.lastSeenMs >= now - freshnessMs) {
            result.push_back(observation);
        }
    }
    return result;
}

void UdpFlowAggregator::pruneOlderThan(const std::int64_t cutoffMs) {
    QMutexLocker locker(&mutex_);
    auto it = storage_.begin();
    while (it != storage_.end()) {
        auto& list = it.value();
        for (int i = list.size() - 1; i >= 0; --i) {
            if (list[i].lastSeenMs < cutoffMs) {
                list.removeAt(i);
            }
        }
        if (list.isEmpty()) {
            it = storage_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace gpd::core
