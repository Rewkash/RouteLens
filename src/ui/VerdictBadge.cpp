#include "ui/VerdictBadge.h"

namespace gpd::core {

QString routeVerdictToString(const RouteVerdict verdict) {
    switch (verdict) {
    case RouteVerdict::Direct:
        return QStringLiteral("DIRECT");
    case RouteVerdict::Vpn:
        return QStringLiteral("VPN");
    case RouteVerdict::SplitTunnel:
        return QStringLiteral("SPLIT");
    case RouteVerdict::Unknown:
        return QStringLiteral("UNKNOWN");
    }
    return QStringLiteral("UNKNOWN");
}

QString protocolToString(const TransportProtocol protocol) {
    switch (protocol) {
    case TransportProtocol::Tcp:
        return QStringLiteral("TCP");
    case TransportProtocol::Udp:
        return QStringLiteral("UDP");
    }
    return QStringLiteral("-");
}

} // namespace gpd::core

namespace gpd::ui {

VerdictBadge::VerdictBadge(QWidget* parent)
    : QLabel(parent) {
    setAlignment(Qt::AlignCenter);
    setMinimumHeight(54);
    setVerdict({});
}

void VerdictBadge::setVerdict(const gpd::core::VerdictSummary& summary) {
    const auto color = [summary]() -> QString {
        switch (summary.verdict) {
        case gpd::core::RouteVerdict::Direct:
            return QStringLiteral("#2f9e44");
        case gpd::core::RouteVerdict::Vpn:
            return QStringLiteral("#f08c00");
        case gpd::core::RouteVerdict::SplitTunnel:
            return QStringLiteral("#c92a2a");
        case gpd::core::RouteVerdict::Unknown:
            return QStringLiteral("#495057");
        }
        return QStringLiteral("#495057");
    }();

    setText(QStringLiteral("%1  %2%").arg(gpd::core::routeVerdictToString(summary.verdict)).arg(summary.confidencePercent));
    setStyleSheet(QStringLiteral("QLabel { background: %1; color: white; border-radius: 10px; font-size: 22px; font-weight: 700; padding: 10px; }").arg(color));
    setToolTip(summary.reason);
}

} // namespace gpd::ui
