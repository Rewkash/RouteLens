#include "core/InterfaceClassifier.h"
#include "core/ConnectionEnricher.h"
#include "core/RouteClassifier.h"
#include "platform/windows/ConnectionScannerWin.h"
#include "platform/windows/InterfaceInspectorWin.h"
#include "platform/windows/ProcessMonitorWin.h"
#include "platform/windows/RouteResolverWin.h"

#include <QCoreApplication>
#include <QHash>

#include <cstdint>
#include <cstdio>

#include <algorithm>

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

int runPureLogicTests() {
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

int runProcessProbe(const QString& processName) {
    gpd::platform::ProcessMonitorWin processMonitor;
    gpd::platform::ConnectionScannerWin scanner;
    gpd::platform::InterfaceInspectorWin interfaceInspector;
    gpd::platform::RouteResolverWin routeResolver;

    const auto processes = processMonitor.listProcesses();
    std::uint32_t pid = 0;
    for (const auto& process : processes) {
        if (process.name.compare(processName, Qt::CaseInsensitive) == 0) {
            pid = process.pid;
            break;
        }
    }

    if (pid == 0) {
        std::fprintf(stderr, "FAIL: process '%s' not found\n", qPrintable(processName));
        return 2;
    }

    const auto rawConnections = scanner.listConnectionsForPid(pid);
    if (rawConnections.isEmpty()) {
        std::fprintf(stderr, "FAIL: process '%s' has no owner-table connections\n", qPrintable(processName));
        return 3;
    }

    const auto interfaces = interfaceInspector.listInterfaces();
    QHash<std::uint32_t, gpd::core::NetworkInterfaceInfo> byIndex;
    for (const auto& iface : interfaces) {
        byIndex.insert(iface.ifIndex, iface);
    }

    const auto enriched = gpd::core::ConnectionEnricher::enrich(rawConnections, byIndex, routeResolver);

    int withInterface = 0;
    int withRemote = 0;
    for (const auto& connection : enriched) {
        if (connection.hasRemoteEndpoint) {
            ++withRemote;
        }
        if (!connection.routedThroughInterfaceName.isEmpty() && connection.routedThroughInterfaceName != QStringLiteral("-")) {
            ++withInterface;
        }
    }

    std::fprintf(stdout, "Probe process: %s\n", qPrintable(processName));
    std::fprintf(stdout, "PID: %u\n", pid);
    std::fprintf(stdout, "Connections total: %lld\n", static_cast<long long>(rawConnections.size()));
    std::fprintf(stdout, "Connections with remote: %d\n", withRemote);
    std::fprintf(stdout, "Connections with resolved interface: %d\n", withInterface);

    if (withInterface <= 0) {
        std::fprintf(stderr, "FAIL: no interface attribution for process '%s'\n", qPrintable(processName));
        return 4;
    }

    std::fprintf(stdout, "OK: interface attribution exists for process '%s'\n", qPrintable(processName));
    return 0;
}

int runContainsProbe(const QString& nameMask) {
    gpd::platform::ProcessMonitorWin processMonitor;
    gpd::platform::ConnectionScannerWin scanner;
    gpd::platform::InterfaceInspectorWin interfaceInspector;
    gpd::platform::RouteResolverWin routeResolver;

    const auto interfaces = interfaceInspector.listInterfaces();
    QHash<std::uint32_t, gpd::core::NetworkInterfaceInfo> byIndex;
    for (const auto& iface : interfaces) {
        byIndex.insert(iface.ifIndex, iface);
    }

    struct ProbeRow {
        std::uint32_t pid{0};
        QString name;
        int totalConnections{0};
        int resolvedInterfaces{0};
    };

    QVector<ProbeRow> rows;
    const auto processes = processMonitor.listProcesses();
    for (const auto& process : processes) {
        if (!process.name.contains(nameMask, Qt::CaseInsensitive)) {
            continue;
        }

        const auto rawConnections = scanner.listConnectionsForPid(process.pid);
        if (rawConnections.isEmpty()) {
            continue;
        }
        const auto enriched = gpd::core::ConnectionEnricher::enrich(rawConnections, byIndex, routeResolver);

        int resolved = 0;
        for (const auto& connection : enriched) {
            if (!connection.routedThroughInterfaceName.isEmpty() && connection.routedThroughInterfaceName != QStringLiteral("-")) {
                ++resolved;
            }
        }

        ProbeRow row;
        row.pid = process.pid;
        row.name = process.name;
        row.totalConnections = rawConnections.size();
        row.resolvedInterfaces = resolved;
        rows.push_back(row);
    }

    if (rows.isEmpty()) {
        std::fprintf(stderr, "FAIL: no matching process with owner-table connections for mask '%s'\n", qPrintable(nameMask));
        return 5;
    }

    std::sort(rows.begin(), rows.end(), [](const ProbeRow& lhs, const ProbeRow& rhs) {
        if (lhs.resolvedInterfaces != rhs.resolvedInterfaces) {
            return lhs.resolvedInterfaces > rhs.resolvedInterfaces;
        }
        return lhs.totalConnections > rhs.totalConnections;
    });

    std::fprintf(stdout, "Probe mask: %s\n", qPrintable(nameMask));
    std::fprintf(stdout, "Candidates with connections:\n");
    for (const auto& row : rows) {
        std::fprintf(stdout, "- %s (pid=%u): total=%d resolved=%d\n", qPrintable(row.name), row.pid, row.totalConnections, row.resolvedInterfaces);
    }

    if (rows.first().resolvedInterfaces <= 0) {
        std::fprintf(stderr, "FAIL: none of matching processes has resolved interface attribution\n");
        return 6;
    }

    std::fprintf(stdout, "OK: best candidate '%s' has interface attribution\n", qPrintable(rows.first().name));
    return 0;
}

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    const auto args = app.arguments();

    if (args.size() >= 3 && args[1] == QStringLiteral("--probe-process")) {
        return runProcessProbe(args[2]);
    }

    if (args.size() >= 3 && args[1] == QStringLiteral("--probe-name-contains")) {
        return runContainsProbe(args[2]);
    }

    return runPureLogicTests();
}
