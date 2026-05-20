#include "core/ConnectionEnricher.h"

#include "core/InterfaceClassifier.h"
#include "core/RouteClassifier.h"
#include "platform/windows/RouteResolverWin.h"

namespace gpd::core {

QVector<ConnectionInfo> ConnectionEnricher::enrich(const QVector<ConnectionInfo>& connections,
                                                   const QHash<std::uint32_t, NetworkInterfaceInfo>& interfacesByIndex,
                                                   const gpd::platform::RouteResolverWin& resolver) {
    QVector<ConnectionInfo> enriched;
    enriched.reserve(connections.size());

    for (auto connection : connections) {
        connection.hasRemoteEndpoint = !connection.remoteAddress.isEmpty() && connection.remoteAddress != QStringLiteral("-") &&
                                       connection.remotePort != 0;
        connection.isPrivateDestination = connection.hasRemoteEndpoint && RouteClassifier::isPrivateAddress(connection.remoteAddress);
        connection.hasPublicRemoteEndpoint = connection.hasRemoteEndpoint && !connection.isPrivateDestination;
        connection.routedThroughInterfaceName = QStringLiteral("-");
        connection.routedThroughKind = InterfaceKind::Unknown;
        connection.perRowVerdict = QStringLiteral("Pending");

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
