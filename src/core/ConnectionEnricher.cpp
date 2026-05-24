#include "core/ConnectionEnricher.h"

#include "core/InterfaceClassifier.h"
#include "core/RouteClassifier.h"
#include "core/UdpFlowAggregator.h"
#include "platform/windows/RouteResolverWin.h"

namespace gpd::core {

namespace {

QString inferProxyStatus(const NetworkInterfaceInfo& interfaceInfo) {
    if (interfaceInfo.kind != InterfaceKind::VpnTunnel) {
        return QStringLiteral("Not proxied");
    }

    const QString blob = (interfaceInfo.friendlyName + QLatin1Char(' ') + interfaceInfo.description + QLatin1Char(' ') +
                          interfaceInfo.adapterName)
                             .toLower();
    if (blob.contains(QStringLiteral("nekobox")) || blob.contains(QStringLiteral("sing-box")) ||
        blob.contains(QStringLiteral("singbox")) || blob.contains(QStringLiteral("v2ray")) ||
        blob.contains(QStringLiteral("xray")) || blob.contains(QStringLiteral("clash")) ||
        blob.contains(QStringLiteral("hiddify")) || blob.contains(QStringLiteral("outline"))) {
        return QStringLiteral("Unknown (TUN interface)");
    }

    return QStringLiteral("Proxied");
}

QString proxyReasonFor(const NetworkInterfaceInfo& interfaceInfo, const QString& routeReason) {
    const QString status = inferProxyStatus(interfaceInfo);
    if (status == QStringLiteral("Not proxied")) {
        return QStringLiteral("Route uses a physical interface; traffic bypasses proxy engines");
    }

    if (status == QStringLiteral("Proxied")) {
        return QStringLiteral("Route uses a VPN tunnel interface; traffic is expected to be tunneled/proxied");
    }

    QString reason = QStringLiteral("Route enters a TUN interface; final proxy decision (DIRECT/PROXY) happens inside tunnel engine");
    if (!routeReason.isEmpty()) {
        reason += QStringLiteral(". Route: ") + routeReason;
    }
    return reason;
}

void finalizeRouteFields(ConnectionInfo& connection, const NetworkInterfaceInfo& interfaceInfo, const QString& routeReason) {
    connection.routedThroughInterfaceName = interfaceInfo.friendlyName;
    connection.routedThroughDescription = interfaceInfo.description;
    connection.routedThroughKind = interfaceInfo.kind;
    connection.proxyStatus = inferProxyStatus(interfaceInfo);
    connection.proxyStatusReason = proxyReasonFor(interfaceInfo, routeReason);

    if (!routeReason.isEmpty()) {
        connection.routedThroughDescription += connection.routedThroughDescription.isEmpty() ? routeReason : QStringLiteral("\n") + routeReason;
    }
    if (!connection.proxyStatus.isEmpty()) {
        connection.routedThroughDescription += connection.routedThroughDescription.isEmpty()
                                                   ? QStringLiteral("Proxy status: %1").arg(connection.proxyStatus)
                                                   : QStringLiteral("\nProxy status: %1").arg(connection.proxyStatus);
    }
    if (!connection.proxyStatusReason.isEmpty()) {
        connection.routedThroughDescription += connection.routedThroughDescription.isEmpty()
                                                   ? connection.proxyStatusReason
                                                   : QStringLiteral("\n") + connection.proxyStatusReason;
    }
}

QString verdictPrefix(const QString& proxyStatus) {
    if (proxyStatus == QStringLiteral("Proxied")) {
        return QStringLiteral("Proxied");
    }
    if (proxyStatus == QStringLiteral("Not proxied")) {
        return QStringLiteral("Direct");
    }
    return QStringLiteral("TUN (proxy unknown)");
}

} // namespace

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
        connection.proxyStatus = QStringLiteral("Unknown");
        connection.proxyStatusReason = QStringLiteral("Route not resolved yet");
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
                    clone.sentPackets = observation.sentPackets;
                    clone.recvPackets = observation.recvPackets;
                    clone.hasRemoteEndpoint = true;
                    clone.isPrivateDestination = RouteClassifier::isPrivateAddress(clone.remoteAddress);
                    clone.hasPublicRemoteEndpoint = !clone.isPrivateDestination;

                    const auto decision = resolver.resolveRouteFor(clone.remoteAddress);
                    if (decision.has_value()) {
                        clone.routedThroughIfIndex = decision->ifIndex;
                        const auto ifaceIt = interfacesByIndex.constFind(decision->ifIndex);
                        if (ifaceIt != interfacesByIndex.cend()) {
                            finalizeRouteFields(clone, ifaceIt.value(), decision->reason);
                            clone.perRowVerdict = QStringLiteral("%1 via %2").arg(verdictPrefix(clone.proxyStatus), ifaceIt->friendlyName);
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
                connection.proxyStatus = QStringLiteral("Unknown");
                connection.proxyStatusReason = QStringLiteral("No UDP destination while ETW is disabled");
            } else {
                connection.remoteAddress = connection.localAddress == QStringLiteral("0.0.0.0") || connection.localAddress == QStringLiteral("::")
                                               ? QStringLiteral("(no UDP traffic observed)")
                                               : QStringLiteral("(UDP listen on %1)").arg(connection.localAddress);
                connection.perRowVerdict = QStringLiteral("No UDP packets seen yet (inferred)");
                connection.proxyStatus = QStringLiteral("Unknown");
                connection.proxyStatusReason = QStringLiteral("No UDP destination observed yet");
            }
            enriched.push_back(connection);
            continue;
        }

        if (!connection.hasRemoteEndpoint) {
            connection.perRowVerdict = QStringLiteral("No remote endpoint");
            connection.proxyStatus = QStringLiteral("Unknown");
            connection.proxyStatusReason = QStringLiteral("Remote endpoint missing");
            enriched.push_back(connection);
            continue;
        }

        if (connection.isPrivateDestination) {
            connection.perRowVerdict = QStringLiteral("Private/LAN");
            connection.proxyStatus = QStringLiteral("Not proxied");
            connection.proxyStatusReason = QStringLiteral("Private/LAN destination");
            enriched.push_back(connection);
            continue;
        }

        const auto decision = resolver.resolveRouteFor(connection.remoteAddress);
        if (!decision.has_value()) {
            connection.perRowVerdict = QStringLiteral("Route unresolved");
            connection.proxyStatus = QStringLiteral("Unknown");
            connection.proxyStatusReason = QStringLiteral("System route lookup failed");
            enriched.push_back(connection);
            continue;
        }

        connection.routedThroughIfIndex = decision->ifIndex;
        const auto interfaceIt = interfacesByIndex.constFind(decision->ifIndex);
        if (interfaceIt == interfacesByIndex.cend()) {
            connection.perRowVerdict = QStringLiteral("Unknown interface");
            connection.proxyStatus = QStringLiteral("Unknown");
            connection.proxyStatusReason = QStringLiteral("Interface metadata not found for route result");
            enriched.push_back(connection);
            continue;
        }

        const auto& interfaceInfo = interfaceIt.value();
        finalizeRouteFields(connection, interfaceInfo, decision->reason);
        connection.observedFromEtw = connection.protocol == TransportProtocol::Udp;
        connection.isInferred = false;
        connection.perRowVerdict = QStringLiteral("%1 via %2").arg(verdictPrefix(connection.proxyStatus), interfaceInfo.friendlyName);

        enriched.push_back(connection);
    }

    return enriched;
}

} // namespace gpd::core
