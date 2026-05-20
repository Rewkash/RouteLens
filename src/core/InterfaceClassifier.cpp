#include "core/InterfaceClassifier.h"

#include <QStringList>

namespace {

bool containsAny(const QString& text, const QStringList& needles) {
    const auto haystack = text.toLower();
    for (const auto& needle : needles) {
        if (haystack.contains(needle)) {
            return true;
        }
    }
    return false;
}

} // namespace

namespace gpd::core {

InterfaceKind InterfaceClassifier::classify(const NetworkInterfaceInfo& interfaceInfo) {
    const auto combined = interfaceInfo.friendlyName + QLatin1Char(' ') + interfaceInfo.description;

    if (interfaceInfo.ifType == 24U) {
        return InterfaceKind::Loopback;
    }

    if (interfaceInfo.ifType == 131U || interfaceInfo.ifType == 23U || interfaceInfo.tunnelType != 0U ||
        containsAny(combined,
                    {QStringLiteral("wintun"), QStringLiteral("wireguard"), QStringLiteral("tailscale"), QStringLiteral("openvpn"),
                     QStringLiteral("tap-windows"), QStringLiteral("tap0901"), QStringLiteral("tunneling"), QStringLiteral("nekobox"),
                     QStringLiteral("singbox"), QStringLiteral("sing-box"), QStringLiteral("outline"), QStringLiteral("hiddify"),
                     QStringLiteral("v2ray"), QStringLiteral("xray"), QStringLiteral("clash"), QStringLiteral("mullvad"),
                     QStringLiteral("protonvpn"), QStringLiteral("nordlynx"), QStringLiteral("expressvpn")})) {
        return InterfaceKind::VpnTunnel;
    }

    if (containsAny(combined, {QStringLiteral("zerotier")})) {
        return InterfaceKind::VirtualOverlay;
    }

    if (containsAny(combined, {QStringLiteral("hyper-v"), QStringLiteral("vmware"), QStringLiteral("virtualbox"), QStringLiteral("vethernet"), QStringLiteral("vmnet")})) {
        return InterfaceKind::VirtualOther;
    }

    if (interfaceInfo.ifType == 71U) {
        return InterfaceKind::WiFi;
    }

    if (interfaceInfo.ifType == 243U || interfaceInfo.ifType == 244U) {
        return InterfaceKind::Cellular;
    }

    if (interfaceInfo.ifType == 6U) {
        return InterfaceKind::Ethernet;
    }

    return InterfaceKind::Unknown;
}

} // namespace gpd::core
