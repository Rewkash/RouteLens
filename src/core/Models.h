#pragma once

#include <QString>
#include <QVector>

#include <cstdint>

namespace gpd::core {

enum class TransportProtocol {
    Tcp,
    Udp,
};

struct ProcessInfo {
    std::uint32_t pid{0};
    QString name;
};

struct ConnectionInfo {
    std::uint32_t pid{0};
    QString localAddress;
    std::uint16_t localPort{0};
    QString remoteAddress;
    std::uint16_t remotePort{0};
    TransportProtocol protocol{TransportProtocol::Udp};
};

enum class RouteVerdict {
    Unknown,
    Direct,
    Vpn,
    SplitTunnel,
};

struct VerdictSummary {
    RouteVerdict verdict{RouteVerdict::Unknown};
    int confidencePercent{0};
    QString reason;
};

QString routeVerdictToString(RouteVerdict verdict);
QString protocolToString(TransportProtocol protocol);

} // namespace gpd::core
