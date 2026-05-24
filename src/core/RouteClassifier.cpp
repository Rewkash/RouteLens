#include "core/RouteClassifier.h"

#include "core/TunnelCorrelator.h"

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

VerdictSummary RouteClassifier::classify(const QVector<ConnectionInfo>& connections, const TunnelCorrelator& correlator, const std::int64_t nowMs) {
    int totalPublic = 0;
    int proxiedConfirmedCount = 0;
    int suspectedCount = 0;
    int directCount = 0;
    int unknownCount = 0;
    int clashTrackedCount = 0;
    QMap<QString, int> tunnelByProcess;

    for (const auto& connection : connections) {
        if (connection.protocol == TransportProtocol::Udp && connection.isInferred) {
            continue;
        }
        if (!connection.hasRemoteEndpoint) {
            continue;
        }
        if (connection.isPrivateDestination) {
            continue;
        }
        ++totalPublic;

        if (connection.clashTracked) {
            ++clashTrackedCount;
            const QString outbound = connection.clashOutbound.toLower();
            if (outbound == QStringLiteral("direct")) {
                ++directCount;
                continue;
            }
            if (outbound == QStringLiteral("reject")) {
                continue;
            }
            ++proxiedConfirmedCount;
            if (!connection.clashOutbound.isEmpty()) {
                tunnelByProcess[connection.clashOutbound] += 1;
            }
            continue;
        }

        if (connection.routedThroughKind == InterfaceKind::Ethernet || connection.routedThroughKind == InterfaceKind::WiFi ||
            connection.routedThroughKind == InterfaceKind::Cellular) {
            ++directCount;
            continue;
        }

        if (connection.routedThroughKind == InterfaceKind::VpnTunnel || connection.routedThroughKind == InterfaceKind::VirtualOverlay) {
            const QString tunnelProcess = correlator.hasActiveTunnel(nowMs);
            if (!tunnelProcess.isEmpty()) {
                ++proxiedConfirmedCount;
                tunnelByProcess[tunnelProcess] += 1;
            } else {
                ++suspectedCount;
            }
            continue;
        }

        ++unknownCount;
    }

    VerdictSummary summary;
    summary.clashTrackedCount = clashTrackedCount;
    summary.clashApiAvailable = clashTrackedCount > 0;
    if (totalPublic == 0) {
        summary.verdict = RouteVerdict::Unknown;
        summary.confidencePercent = 0;
        bool hasInferredUdp = false;
        for (const auto& connection : connections) {
            if (connection.protocol == TransportProtocol::Udp && connection.isInferred) {
                hasInferredUdp = true;
                break;
            }
        }
        summary.reason = hasInferredUdp ? QStringLiteral("Only inferred UDP routes; enable ETW for real attribution")
                                        : QStringLiteral("Only LAN/private destinations");
        return summary;
    }

    QString topProcess;
    int topCount = 0;
    for (auto it = tunnelByProcess.cbegin(); it != tunnelByProcess.cend(); ++it) {
        if (it.value() > topCount) {
            topCount = it.value();
            topProcess = it.key();
        }
    }

    if (proxiedConfirmedCount == totalPublic) {
        summary.verdict = RouteVerdict::Vpn;
        summary.confidencePercent = qMin(95, 50 + 10 * qMin(totalPublic, 5));
        summary.tunnelProcessName = topProcess;
        summary.reason = QStringLiteral("All %1 endpoints proxied via %2").arg(totalPublic).arg(topProcess.isEmpty() ? QStringLiteral("tunnel process") : topProcess);
        if (clashTrackedCount > 0) {
            summary.reason += QStringLiteral(" (Clash API tracked %1/%2)").arg(clashTrackedCount).arg(totalPublic);
            summary.confidencePercent = qMax(summary.confidencePercent, 95);
        }
        return summary;
    }

    if (directCount == totalPublic) {
        summary.verdict = RouteVerdict::Direct;
        summary.confidencePercent = qMin(95, 50 + 10 * qMin(totalPublic, 5));
        summary.reason = QStringLiteral("%1/%1 game endpoints routed via physical interfaces").arg(totalPublic);
        if (clashTrackedCount > 0) {
            summary.reason += QStringLiteral(" (Clash API tracked %1/%2)").arg(clashTrackedCount).arg(totalPublic);
            summary.confidencePercent = qMax(summary.confidencePercent, 95);
        }
        return summary;
    }

    if (suspectedCount == totalPublic) {
        summary.verdict = RouteVerdict::TunneledSuspected;
        summary.confidencePercent = 50;
        summary.reason = QStringLiteral("Traffic uses tunnel interfaces, but no active tunnel-process traffic was observed in last 2s");
        return summary;
    }

    if (directCount > 0 && (proxiedConfirmedCount + suspectedCount) > 0) {
        summary.verdict = RouteVerdict::SplitTunnel;
        const int divergence = qMin(directCount, proxiedConfirmedCount + suspectedCount);
        summary.confidencePercent = qMin(90, 40 + 10 * qMin(divergence, 5));
        summary.reason = QStringLiteral("Split routing: %1 proxied (confirmed), %2 direct, %3 tunneled (suspected)")
                             .arg(proxiedConfirmedCount)
                             .arg(directCount)
                             .arg(suspectedCount);
        summary.tunnelProcessName = topProcess;
        return summary;
    }

    if (proxiedConfirmedCount > 0 && suspectedCount > 0 && directCount == 0) {
        summary.verdict = RouteVerdict::Vpn;
        summary.confidencePercent = 72;
        summary.tunnelProcessName = topProcess;
        summary.reason = QStringLiteral("Tunnel usage partially confirmed by %1; some endpoints currently only suspected")
                             .arg(topProcess.isEmpty() ? QStringLiteral("active tunnel process") : topProcess);
        return summary;
    }

    summary.verdict = RouteVerdict::Unknown;
    summary.confidencePercent = unknownCount > 0 ? 40 : 25;
    summary.reason = QStringLiteral("Insufficient route attribution confidence");
    return summary;
}

} // namespace gpd::core
