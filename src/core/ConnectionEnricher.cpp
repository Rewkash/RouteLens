#include "core/ConnectionEnricher.h"

#include "core/InterfaceClassifier.h"
#include "core/RouteClassifier.h"
#include "core/UdpFlowAggregator.h"
#include "platform/windows/RouteResolverWin.h"

namespace gpd::core {

QVector<ConnectionInfo> ConnectionEnricher::enrich(const QVector<ConnectionInfo>& connections,
                                                   const QHash<std::uint32_t, NetworkInterfaceInfo>& interfacesByIndex,
                                                   const gpd::platform::RouteResolverWin& resolver,
                                                   const UdpFlowAggregator& udpFlows,
                                                   const bool etwRunning) {
    QVector<ConnectionInfo> enriched;
    enriched.reserve(connections.size() * 2);

    for (auto connection : connections) {
        connection.hasRemoteEndpoint = !connection.remoteAddress.isEmpty() && connection.remoteAddress != QStringLiteral("-") &&
                                       connection.remotePort != 0;
        connection.isPrivateDestination = connection.hasRemoteEndpoint && RouteClassifier::isPrivateAddress(connection.remoteAddress);
        connection.hasPublicRemoteEndpoint = connection.hasRemoteEndpoint && !connection.isPrivateDestination;
        connection.routedThroughInterfaceName = QStringLiteral("-");
        connection.routedThroughKind = InterfaceKind::Unknown;
        connection.perRowVerdict = QStringLiteral("Pending");

        if (!connection.hasRemoteEndpoint && connection.protocol == TransportProtocol::Udp) {
            UdpEndpointKey key;
            key.pid = connection.pid;
            key.localAddress = connection.localAddress;
            key.localPort = connection.localPort;
            const auto observations = udpFlows.endpointsFor(key, 30000);

            if (!observations.isEmpty()) {
                for (const auto& observation : observations) {
                    auto clone = connection;
                    clone.remoteAddress = observation.remoteAddress;
                    clone.remotePort = observation.remotePort;
                    clone.observedFromEtw = true;
                    clone.isInferred = false;
                    clone.lastSeenMs = observation.lastSeenMs;
                    clone.sentBytes = observation.sentBytes;
                    clone.recvBytes = observation.recvBytes;
                    clone.hasRemoteEndpoint = true;
                    clone.isPrivateDestination = RouteClassifier::isPrivateAddress(clone.remoteAddress);
                    clone.hasPublicRemoteEndpoint = !clone.isPrivateDestination;

                    const auto decision = resolver.resolveRouteFor(clone.remoteAddress);
                    if (decision.has_value()) {
                        clone.routedThroughIfIndex = decision->ifIndex;
                        const auto ifaceIt = interfacesByIndex.constFind(decision->ifIndex);
                        if (ifaceIt != interfacesByIndex.cend()) {
                            clone.routedThroughInterfaceName = ifaceIt->friendlyName;
                            clone.routedThroughDescription = ifaceIt->description;
                            clone.routedThroughKind = ifaceIt->kind;
                            clone.perRowVerdict = QStringLiteral("Via %1").arg(ifaceIt->friendlyName);
                        }
                    }

                    enriched.push_back(clone);
                }
                continue;
            }

            connection.observedFromEtw = false;
            connection.isInferred = true;
            if (!etwRunning) {
                connection.remoteAddress = QStringLiteral("(ETW disabled - UDP destinations unavailable)");
                connection.perRowVerdict = QStringLiteral("ETW disabled - inferred");
            } else {
                connection.remoteAddress = connection.localAddress == QStringLiteral("0.0.0.0") || connection.localAddress == QStringLiteral("::")
                                               ? QStringLiteral("(no UDP traffic observed)")
                                               : QStringLiteral("(UDP listen on %1)").arg(connection.localAddress);
                connection.perRowVerdict = QStringLiteral("No UDP packets seen yet (inferred)");
            }
            enriched.push_back(connection);
            continue;
        }

        if (!connection.hasRemoteEndpoint) {
            connection.perRowVerdict = QStringLiteral("No remote endpoint");
            enriched.push_back(connection);
            continue;
        }

        if (connection.isPrivateDestination) {
            connection.perRowVerdict = QStringLiteral("Private/LAN");
            enriched.push_back(connection);
            continue;
        }

        const auto decision = resolver.resolveRouteFor(connection.remoteAddress);
        if (!decision.has_value()) {
            connection.perRowVerdict = QStringLiteral("Route unresolved");
            enriched.push_back(connection);
            continue;
        }

        connection.routedThroughIfIndex = decision->ifIndex;
        const auto interfaceIt = interfacesByIndex.constFind(decision->ifIndex);
        if (interfaceIt == interfacesByIndex.cend()) {
            connection.perRowVerdict = QStringLiteral("Unknown interface");
            enriched.push_back(connection);
            continue;
        }

        const auto& interfaceInfo = interfaceIt.value();
        connection.routedThroughInterfaceName = interfaceInfo.friendlyName;
        connection.routedThroughDescription = interfaceInfo.description;
        connection.routedThroughKind = interfaceInfo.kind;
        connection.observedFromEtw = connection.protocol == TransportProtocol::Udp;
        connection.isInferred = false;

        switch (interfaceInfo.kind) {
        case InterfaceKind::VpnTunnel:
            connection.perRowVerdict = QStringLiteral("Via VPN (%1)").arg(interfaceInfo.friendlyName);
            break;
        case InterfaceKind::VirtualOverlay:
            connection.perRowVerdict = QStringLiteral("Via Overlay (%1)").arg(interfaceInfo.friendlyName);
            break;
        case InterfaceKind::Ethernet:
        case InterfaceKind::WiFi:
        case InterfaceKind::Cellular:
            connection.perRowVerdict = QStringLiteral("Via %1").arg(interfaceInfo.friendlyName);
            break;
        default:
            connection.perRowVerdict = QStringLiteral("Via %1").arg(interfaceInfo.friendlyName);
            break;
        }

        enriched.push_back(connection);
    }

    return enriched;
}

} // namespace gpd::core
