#include "ui/VerdictBadge.h"

namespace gpd::core {

QString routeVerdictToString(const RouteVerdict verdict) {
    switch (verdict) {
    case RouteVerdict::Direct:
        return QStringLiteral("Напрямую");
    case RouteVerdict::Vpn:
        return QStringLiteral("Через прокси (подтверждено)");
    case RouteVerdict::SplitTunnel:
        return QStringLiteral("Split-tunnel");
    case RouteVerdict::TunneledSuspected:
        return QStringLiteral("Туннелируется (предположительно)");
    case RouteVerdict::Unknown:
        return QStringLiteral("Неизвестно");
    }
    return QStringLiteral("Неизвестно");
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

QString interfaceKindToString(const InterfaceKind kind) {
    switch (kind) {
    case InterfaceKind::Loopback:
        return QStringLiteral("Loopback");
    case InterfaceKind::Ethernet:
        return QStringLiteral("Ethernet");
    case InterfaceKind::WiFi:
        return QStringLiteral("Wi-Fi");
    case InterfaceKind::Cellular:
        return QStringLiteral("Сотовая сеть");
    case InterfaceKind::VpnTunnel:
        return QStringLiteral("VPN-туннель");
    case InterfaceKind::VirtualOverlay:
        return QStringLiteral("Виртуальный оверлей");
    case InterfaceKind::VirtualOther:
        return QStringLiteral("Другое виртуальное");
    case InterfaceKind::Unknown:
        return QStringLiteral("Неизвестно");
    }
    return QStringLiteral("Неизвестно");
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
            return QStringLiteral("#1c7ed6");
        case gpd::core::RouteVerdict::SplitTunnel:
            return QStringLiteral("#f08c00");
        case gpd::core::RouteVerdict::TunneledSuspected:
            return QStringLiteral("#e67700");
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
