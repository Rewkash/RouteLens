#include "core/TunnelProcessRegistry.h"

#include <QHash>

namespace {

QString normalizeProcessName(const QString& rawName) {
    QString name = rawName.trimmed().toLower();
    const int slashPos = qMax(name.lastIndexOf(QLatin1Char('/')), name.lastIndexOf(QLatin1Char('\\')));
    if (slashPos >= 0 && slashPos + 1 < name.size()) {
        name = name.mid(slashPos + 1);
    }
    if (name.endsWith(QStringLiteral(".exe"))) {
        name.chop(4);
    }
    return name;
}

const QHash<QString, QString>& knownProcessMap() {
    static const QHash<QString, QString> map = {
        {QStringLiteral("wireguard"), QStringLiteral("vpn")},
        {QStringLiteral("wg"), QStringLiteral("vpn")},
        {QStringLiteral("openvpn"), QStringLiteral("vpn")},
        {QStringLiteral("openvpn-gui"), QStringLiteral("vpn")},
        {QStringLiteral("ovpn"), QStringLiteral("vpn")},
        {QStringLiteral("softether"), QStringLiteral("vpn")},
        {QStringLiteral("vpnclient"), QStringLiteral("vpn")},
        {QStringLiteral("protonvpn-service"), QStringLiteral("vpn")},
        {QStringLiteral("mullvadvpn-app"), QStringLiteral("vpn")},
        {QStringLiteral("mullvad-daemon"), QStringLiteral("vendor-vpn")},
        {QStringLiteral("expressvpn"), QStringLiteral("vpn")},
        {QStringLiteral("nordvpn-service"), QStringLiteral("vpn")},
        {QStringLiteral("nordvpn"), QStringLiteral("vpn")},
        {QStringLiteral("nekobox"), QStringLiteral("proxy")},
        {QStringLiteral("nekobox_core"), QStringLiteral("proxy")},
        {QStringLiteral("sing-box"), QStringLiteral("proxy")},
        {QStringLiteral("singbox"), QStringLiteral("proxy")},
        {QStringLiteral("v2ray"), QStringLiteral("proxy")},
        {QStringLiteral("xray"), QStringLiteral("proxy")},
        {QStringLiteral("xray-core"), QStringLiteral("proxy")},
        {QStringLiteral("clash"), QStringLiteral("proxy")},
        {QStringLiteral("clash-verge"), QStringLiteral("proxy")},
        {QStringLiteral("clash-meta"), QStringLiteral("proxy")},
        {QStringLiteral("mihomo"), QStringLiteral("proxy")},
        {QStringLiteral("hiddify-next"), QStringLiteral("proxy")},
        {QStringLiteral("hiddify"), QStringLiteral("proxy")},
        {QStringLiteral("outline-client"), QStringLiteral("proxy")},
        {QStringLiteral("shadowsocks"), QStringLiteral("proxy")},
        {QStringLiteral("ss-local"), QStringLiteral("proxy")},
        {QStringLiteral("tun2socks"), QStringLiteral("proxy")},
        {QStringLiteral("tun2socks5"), QStringLiteral("proxy")},
        {QStringLiteral("tailscaled"), QStringLiteral("overlay")},
        {QStringLiteral("tailscale"), QStringLiteral("overlay")},
        {QStringLiteral("zerotier_one"), QStringLiteral("overlay")},
        {QStringLiteral("zerotier-one"), QStringLiteral("overlay")},
        {QStringLiteral("headscale"), QStringLiteral("overlay")},
        {QStringLiteral("cloudflare-warp-svc"), QStringLiteral("vendor-vpn")},
        {QStringLiteral("warp-svc"), QStringLiteral("vendor-vpn")},
        {QStringLiteral("surfsharkservice"), QStringLiteral("vendor-vpn")},
        {QStringLiteral("ipvanish"), QStringLiteral("vendor-vpn")},
    };
    return map;
}

} // namespace

namespace gpd::core {

bool TunnelProcessRegistry::isKnownTunnel(const QString& processName) {
    return knownProcessMap().contains(normalizeProcessName(processName));
}

QString TunnelProcessRegistry::categoryFor(const QString& processName) {
    return knownProcessMap().value(normalizeProcessName(processName));
}

QVector<QString> TunnelProcessRegistry::knownNames() {
    QVector<QString> out;
    out.reserve(knownProcessMap().size());
    for (auto it = knownProcessMap().cbegin(); it != knownProcessMap().cend(); ++it) {
        out.push_back(it.key());
    }
    return out;
}

} // namespace gpd::core
