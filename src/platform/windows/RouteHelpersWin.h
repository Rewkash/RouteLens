#pragma once

#include <QString>
#include <cstdint>

namespace gpd::platform {

QString findPhysicalDefaultGateway();

QString findPhysicalLocalIPv4();

struct TunnelStats {
    bool found{false};
    QString friendlyName;
    quint32 ifIndex{0};
    quint64 inOctets{0};
    quint64 outOctets{0};
};

TunnelStats aggregateTunnelStats();

TunnelStats aggregatePhysicalStats();

} // namespace gpd::platform
