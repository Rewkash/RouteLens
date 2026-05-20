#pragma once

#include <QString>
#include <QStringList>
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

enum class InterfaceKind {
    Unknown,
    Loopback,
    Ethernet,
    WiFi,
    Cellular,
    VpnTunnel,
    VirtualOverlay,
    VirtualOther,
};

struct ConnectionInfo {
    std::uint32_t pid{0};
    QString localAddress;
    std::uint16_t localPort{0};
    QString remoteAddress;
    std::uint16_t remotePort{0};
    TransportProtocol protocol{TransportProtocol::Udp};
    std::uint32_t routedThroughIfIndex{0};
    QString routedThroughInterfaceName;
    QString routedThroughDescription;
    InterfaceKind routedThroughKind{InterfaceKind::Unknown};
    QString perRowVerdict;
    bool isPrivateDestination{false};
    bool hasRemoteEndpoint{false};
    bool hasPublicRemoteEndpoint{false};
};

struct NetworkInterfaceInfo {
    std::uint32_t ifIndex{0};
    std::uint64_t luid{0};
    QString friendlyName;
    QString description;
    std::uint32_t ifType{0};
    std::uint32_t tunnelType{0};
    std::uint32_t operStatus{0};
    QStringList unicastAddresses;
    QStringList gatewayAddresses;
    QString macAddress;
    QString dnsSuffix;
    InterfaceKind kind{InterfaceKind::Unknown};
};

struct RoutingDecision {
    std::uint32_t ifIndex{0};
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
QString interfaceKindToString(InterfaceKind kind);

} // namespace gpd::core
