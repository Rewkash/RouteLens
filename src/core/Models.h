#pragma once

#include <QString>
#include <QStringList>
#include <QVector>
#include <QMetaType>

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

struct GeoInfo {
    QString countryIsoCode;
    QString countryName;
    QString asnNumber;
    QString asnOrganization;
    bool isPrivate{false};
    bool resolved{false};
};

struct PingAggregate {
    int rttMinMs{-1};
    int rttAvgMs{-1};
    int rttMaxMs{-1};
    double jitterMs{0.0};
    double lossPercent{0.0};
    int samplesInWindow{0};
    int totalSamples{0};
    bool icmpBlocked{false};
    bool unreachable{false};
    std::int64_t lastSampleAtMs{0};
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
    bool observedFromEtw{false};
    bool isInferred{false};
    std::int64_t lastSeenMs{0};
    std::uint64_t sentBytes{0};
    std::uint64_t recvBytes{0};
    bool isPrivateDestination{false};
    bool hasRemoteEndpoint{false};
    bool hasPublicRemoteEndpoint{false};
    GeoInfo geoInfo;
    PingAggregate pingAggregate;
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

struct UdpFlowEvent {
    std::uint32_t pid{0};
    QString localAddress;
    std::uint16_t localPort{0};
    QString remoteAddress;
    std::uint16_t remotePort{0};
    bool isIPv6{false};
    bool isSend{false};
    std::int64_t timestampMs{0};
    std::uint32_t sizeBytes{0};
};

struct UdpEndpointKey {
    std::uint32_t pid{0};
    QString localAddress;
    std::uint16_t localPort{0};

    bool operator==(const UdpEndpointKey& other) const noexcept {
        return pid == other.pid && localAddress == other.localAddress && localPort == other.localPort;
    }
};

struct UdpEndpointObservation {
    QString remoteAddress;
    std::uint16_t remotePort{0};
    bool isIPv6{false};
    std::int64_t lastSeenMs{0};
    std::int64_t firstSeenMs{0};
    std::uint64_t sentBytes{0};
    std::uint64_t recvBytes{0};
    std::uint64_t sentPackets{0};
    std::uint64_t recvPackets{0};
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

inline size_t qHash(const gpd::core::UdpEndpointKey& key, const size_t seed = 0) noexcept {
    return qHash(key.pid, seed) ^ qHash(key.localAddress, seed) ^ qHash(key.localPort, seed);
}

Q_DECLARE_METATYPE(gpd::core::UdpFlowEvent)
Q_DECLARE_METATYPE(QVector<gpd::core::UdpFlowEvent>)
