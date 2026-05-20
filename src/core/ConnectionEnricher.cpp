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

    QVector<ConnectionInfo> staged;
    staged.reserve(connections.size());

    for (auto connection : connections) {
        connection.hasRemoteEndpoint = !connection.remoteAddress.isEmpty() && connection.remoteAddress != QStringLiteral("-") &&
                                       connection.remotePort != 0;
        connection.isPrivateDestination = connection.hasRemoteEndpoint && RouteClassifier::isPrivateAddress(connection.remoteAddress);
        connection.hasPublicRemoteEndpoint = connection.hasRemoteEndpoint && !connection.isPrivateDestination;
        connection.routedThroughInterfaceName = QStringLiteral("-");
        connection.routedThroughKind = InterfaceKind::Unknown;
        connection.perRowVerdict = QStringLiteral("Pending");

        auto assignFromInterface = [&](const NetworkInterfaceInfo& interfaceInfo) {
            connection.routedThroughIfIndex = interfaceInfo.ifIndex;
            connection.routedThroughInterfaceName = interfaceInfo.friendlyName;
            connection.routedThroughDescription = interfaceInfo.description;
            connection.routedThroughKind = interfaceInfo.kind;
        };

        auto assignPerRowVerdict = [&]() {
            switch (connection.routedThroughKind) {
            case InterfaceKind::VpnTunnel:
                connection.perRowVerdict = QStringLiteral("Via VPN (%1)").arg(connection.routedThroughInterfaceName);
                break;
            case InterfaceKind::VirtualOverlay:
                connection.perRowVerdict = QStringLiteral("Via Overlay (%1)").arg(connection.routedThroughInterfaceName);
                break;
            case InterfaceKind::Ethernet:
            case InterfaceKind::WiFi:
            case InterfaceKind::Cellular:
                connection.perRowVerdict = QStringLiteral("Via %1").arg(connection.routedThroughInterfaceName);
                break;
            default:
                connection.perRowVerdict = connection.routedThroughInterfaceName == QStringLiteral("-")
                                               ? QStringLiteral("Unknown interface")
                                               : QStringLiteral("Via %1").arg(connection.routedThroughInterfaceName);
                break;
            }
        };

        auto findInterfaceByLocalAddress = [&]() -> const NetworkInterfaceInfo* {
            if (connection.localAddress.isEmpty() || connection.localAddress == QStringLiteral("-") || connection.localAddress == QStringLiteral("0.0.0.0") ||
                connection.localAddress == QStringLiteral("::")) {
                return nullptr;
            }

            for (auto it = interfacesByIndex.cbegin(); it != interfacesByIndex.cend(); ++it) {
                const auto& iface = it.value();
                for (const auto& ip : iface.unicastAddresses) {
                    if (ip == connection.localAddress) {
                        return &iface;
                    }
                }
            }
            return nullptr;
        };

        if (!connection.hasRemoteEndpoint) {
            const auto* localIface = findInterfaceByLocalAddress();
            if (localIface != nullptr) {
                assignFromInterface(*localIface);
                assignPerRowVerdict();
                connection.perRowVerdict += QStringLiteral(" (local-bound)");
            } else {
                connection.perRowVerdict = QStringLiteral("No remote endpoint");
            }

            if (connection.remoteAddress.isEmpty() || connection.remoteAddress == QStringLiteral("-")) {
                if (!connection.localAddress.isEmpty() && connection.localAddress != QStringLiteral("0.0.0.0") && connection.localAddress != QStringLiteral("::")) {
                    connection.remoteAddress = QStringLiteral("%1 (udp-unconnected)").arg(connection.localAddress);
                }
            }
            staged.push_back(connection);
            continue;
        }

        if (connection.isPrivateDestination) {
            connection.perRowVerdict = QStringLiteral("Private/LAN");
            staged.push_back(connection);
            continue;
        }

        const auto decision = resolver.resolveRouteFor(connection.remoteAddress);
        if (!decision.has_value()) {
            connection.perRowVerdict = QStringLiteral("Route unresolved");
            staged.push_back(connection);
            continue;
        }

        connection.routedThroughIfIndex = decision->ifIndex;
        const auto interfaceIt = interfacesByIndex.constFind(decision->ifIndex);
        if (interfaceIt == interfacesByIndex.cend()) {
            connection.perRowVerdict = QStringLiteral("Unknown interface");
            staged.push_back(connection);
            continue;
        }

        const auto& interfaceInfo = interfaceIt.value();
        assignFromInterface(interfaceInfo);
        assignPerRowVerdict();

        staged.push_back(connection);
    }

    QHash<std::uint32_t, int> byInterfaceVotes;
    for (const auto& connection : staged) {
        if (connection.routedThroughIfIndex != 0 && !connection.routedThroughInterfaceName.isEmpty() && connection.routedThroughInterfaceName != QStringLiteral("-")) {
            byInterfaceVotes[connection.routedThroughIfIndex] = byInterfaceVotes.value(connection.routedThroughIfIndex) + 1;
        }
    }

    std::uint32_t majorityIfIndex = 0;
    int bestVotes = 0;
    for (auto it = byInterfaceVotes.cbegin(); it != byInterfaceVotes.cend(); ++it) {
        if (it.value() > bestVotes) {
            bestVotes = it.value();
            majorityIfIndex = it.key();
        }
    }

    std::optional<RoutingDecision> defaultDecision;
    if (majorityIfIndex == 0) {
        defaultDecision = resolver.resolveRouteFor(QStringLiteral("1.1.1.1"));
        if (!defaultDecision.has_value()) {
            defaultDecision = resolver.resolveRouteFor(QStringLiteral("2606:4700:4700::1111"));
        }
    }

    for (auto& connection : staged) {
        if (connection.hasRemoteEndpoint) {
            enriched.push_back(connection);
            continue;
        }
        if (!connection.routedThroughInterfaceName.isEmpty() && connection.routedThroughInterfaceName != QStringLiteral("-")) {
            enriched.push_back(connection);
            continue;
        }

        std::uint32_t inferredIfIndex = majorityIfIndex;
        if (inferredIfIndex == 0 && defaultDecision.has_value()) {
            inferredIfIndex = defaultDecision->ifIndex;
        }

        if (inferredIfIndex != 0) {
            const auto it = interfacesByIndex.constFind(inferredIfIndex);
            if (it != interfacesByIndex.cend()) {
                const auto& iface = it.value();
                connection.routedThroughIfIndex = iface.ifIndex;
                connection.routedThroughInterfaceName = iface.friendlyName;
                connection.routedThroughDescription = iface.description;
                connection.routedThroughKind = iface.kind;
                connection.perRowVerdict = QStringLiteral("Inferred via %1 (UDP unconnected)").arg(iface.friendlyName);
            }
        }

        enriched.push_back(connection);
    }

    return enriched;
}

} // namespace gpd::core
