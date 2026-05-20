#include "core/InterfaceClassifier.h"
#include "core/RouteClassifier.h"

namespace {

int failures = 0;

void expectTrue(const bool value) {
    if (!value) {
        ++failures;
    }
}

gpd::core::NetworkInterfaceInfo makeInterface(const QString& friendlyName, const QString& description, const std::uint32_t ifType = 0,
                                              const std::uint32_t tunnelType = 0) {
    gpd::core::NetworkInterfaceInfo info;
    info.friendlyName = friendlyName;
    info.description = description;
    info.ifType = ifType;
    info.tunnelType = tunnelType;
    return info;
}

gpd::core::ConnectionInfo makeConnection(const gpd::core::InterfaceKind kind, const QString& ifName, const QString& remote) {
    gpd::core::ConnectionInfo connection;
    connection.remoteAddress = remote;
    connection.remotePort = 443;
    connection.hasRemoteEndpoint = true;
    connection.isPrivateDestination = gpd::core::RouteClassifier::isPrivateAddress(remote);
    connection.routedThroughKind = kind;
    connection.routedThroughInterfaceName = ifName;
    return connection;
}

} // namespace

int main() {
    using gpd::core::InterfaceClassifier;
    using gpd::core::InterfaceKind;
    using gpd::core::RouteClassifier;
    using gpd::core::RouteVerdict;

    expectTrue(InterfaceClassifier::classify(makeInterface(QStringLiteral("nekobox-tun"), QStringLiteral("WinTun Userspace Tunnel"), 131)) == InterfaceKind::VpnTunnel);
    expectTrue(InterfaceClassifier::classify(makeInterface(QStringLiteral("ZeroTier One [ab]"), QStringLiteral("ZeroTier adapter"), 6)) == InterfaceKind::VirtualOverlay);
    expectTrue(InterfaceClassifier::classify(makeInterface(QStringLiteral("Realtek PCIe GbE"), QStringLiteral("Ethernet adapter"), 6)) == InterfaceKind::Ethernet);
    expectTrue(InterfaceClassifier::classify(makeInterface(QStringLiteral("Intel Wi-Fi 6"), QStringLiteral("Wireless adapter"), 71)) == InterfaceKind::WiFi);
    expectTrue(InterfaceClassifier::classify(makeInterface(QStringLiteral("Loopback Pseudo-Interface"), QStringLiteral("Loopback"), 24)) == InterfaceKind::Loopback);

    {
        QVector<gpd::core::ConnectionInfo> connections;
        connections.push_back(makeConnection(InterfaceKind::VpnTunnel, QStringLiteral("nekobox-tun"), QStringLiteral("8.8.8.8")));
        connections.push_back(makeConnection(InterfaceKind::VpnTunnel, QStringLiteral("nekobox-tun"), QStringLiteral("1.1.1.1")));
        connections.push_back(makeConnection(InterfaceKind::VpnTunnel, QStringLiteral("nekobox-tun"), QStringLiteral("9.9.9.9")));
        const auto verdict = RouteClassifier::classify(connections);
        expectTrue(verdict.verdict == RouteVerdict::Vpn);
        expectTrue(verdict.confidencePercent >= 70);
    }

    {
        QVector<gpd::core::ConnectionInfo> connections;
        connections.push_back(makeConnection(InterfaceKind::Ethernet, QStringLiteral("Ethernet"), QStringLiteral("8.8.8.8")));
        connections.push_back(makeConnection(InterfaceKind::VpnTunnel, QStringLiteral("nekobox-tun"), QStringLiteral("1.1.1.1")));
        connections.push_back(makeConnection(InterfaceKind::Ethernet, QStringLiteral("Ethernet"), QStringLiteral("9.9.9.9")));
        const auto verdict = RouteClassifier::classify(connections);
        expectTrue(verdict.verdict == RouteVerdict::SplitTunnel);
    }

    {
        QVector<gpd::core::ConnectionInfo> connections;
        connections.push_back(makeConnection(InterfaceKind::Ethernet, QStringLiteral("Ethernet"), QStringLiteral("192.168.1.25")));
        connections.push_back(makeConnection(InterfaceKind::Ethernet, QStringLiteral("Ethernet"), QStringLiteral("10.0.0.55")));
        const auto verdict = RouteClassifier::classify(connections);
        expectTrue(verdict.verdict == RouteVerdict::Unknown);
    }

    return failures == 0 ? 0 : 1;
}
