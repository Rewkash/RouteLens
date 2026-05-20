#include "core/RouteClassifier.h"

#include <QHostAddress>
#include <QMap>

namespace gpd::core {

bool RouteClassifier::isPrivateAddress(const QString& ipAddress) {
    QHostAddress address;
    if (!address.setAddress(ipAddress)) {
        return false;
    }

    if (address.isLoopback() || address.isLinkLocal()) {
        return true;
    }

    if (address.protocol() == QAbstractSocket::IPv4Protocol) {
        const auto ipv4 = address.toIPv4Address();
        if ((ipv4 & 0xFF000000U) == 0x0A000000U) {
            return true;
        }
        if ((ipv4 & 0xFFF00000U) == 0xAC100000U) {
            return true;
        }
        if ((ipv4 & 0xFFFF0000U) == 0xC0A80000U) {
            return true;
        }
        if ((ipv4 & 0xFFC00000U) == 0x64400000U) {
            return true;
        }
        if ((ipv4 & 0xFFFF0000U) == 0xA9FE0000U) {
            return true;
        }
        return false;
    }

    if (address.protocol() == QAbstractSocket::IPv6Protocol) {
        const auto bytes = address.toIPv6Address();
        if ((bytes[0] & 0xFEU) == 0xFCU) {
            return true;
        }
        return false;
    }

    return false;
}

VerdictSummary RouteClassifier::classify(const QVector<ConnectionInfo>& connections) {
    int totalPublic = 0;
    int vpnCount = 0;
    int directCount = 0;
    int overlayCount = 0;
    QString firstVpnInterface;
    QMap<InterfaceKind, int> byKind;

    for (const auto& connection : connections) {
        if (!connection.hasRemoteEndpoint) {
            continue;
        }
        if (connection.isPrivateDestination) {
            continue;
        }
        ++totalPublic;
        byKind[connection.routedThroughKind] += 1;
        if (connection.routedThroughKind == InterfaceKind::VpnTunnel) {
            ++vpnCount;
            if (firstVpnInterface.isEmpty()) {
                firstVpnInterface = connection.routedThroughInterfaceName;
            }
        } else if (connection.routedThroughKind == InterfaceKind::Ethernet || connection.routedThroughKind == InterfaceKind::WiFi ||
                   connection.routedThroughKind == InterfaceKind::Cellular) {
            ++directCount;
        } else if (connection.routedThroughKind == InterfaceKind::VirtualOverlay) {
            ++overlayCount;
        }
    }

    VerdictSummary summary;
    if (totalPublic == 0) {
        summary.verdict = RouteVerdict::Unknown;
        summary.confidencePercent = 0;
        summary.reason = QStringLiteral("Only LAN/private destinations");
        return summary;
    }

    if (vpnCount == totalPublic) {
        summary.verdict = RouteVerdict::Vpn;
        summary.confidencePercent = qMin(95, 50 + 10 * qMin(totalPublic, 5));
        summary.reason = QStringLiteral("%1/%1 game endpoints routed via VPN tunnel: %2").arg(totalPublic).arg(firstVpnInterface);
        return summary;
    }

    if (directCount == totalPublic) {
        summary.verdict = RouteVerdict::Direct;
        summary.confidencePercent = qMin(95, 50 + 10 * qMin(totalPublic, 5));
        summary.reason = QStringLiteral("%1/%1 game endpoints routed via physical interfaces").arg(totalPublic);
        return summary;
    }

    if (vpnCount > 0 && directCount > 0) {
        summary.verdict = RouteVerdict::SplitTunnel;
        const int divergence = qMin(vpnCount, directCount);
        summary.confidencePercent = qMin(90, 40 + 10 * qMin(divergence, 5));
        summary.reason = QStringLiteral("Split routing detected: %1 via VPN and %2 direct").arg(vpnCount).arg(directCount);
        return summary;
    }

    if (overlayCount == totalPublic && vpnCount == 0) {
        summary.verdict = RouteVerdict::Vpn;
        summary.confidencePercent = 70;
        summary.reason = QStringLiteral("overlay network detected");
        return summary;
    }

    summary.verdict = RouteVerdict::Unknown;
    summary.confidencePercent = 40;
    summary.reason = QStringLiteral("Insufficient route attribution confidence");
    return summary;
}

} // namespace gpd::core
