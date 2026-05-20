#include "core/InterfaceClassifier.h"
#include "core/ConnectionEnricher.h"
#include "core/RouteClassifier.h"
#include "core/UdpFlowAggregator.h"
#include "platform/windows/ConnectionScannerWin.h"
#include "platform/windows/EtwNetworkTap.h"
#include "platform/windows/InterfaceInspectorWin.h"
#include "platform/windows/ProcessMonitorWin.h"
#include "platform/windows/RouteResolverWin.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QHostAddress>
#include <QUdpSocket>
#include <QTimer>

#include <iostream>

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

QString protocolText(const gpd::core::TransportProtocol protocol) {
    return protocol == gpd::core::TransportProtocol::Tcp ? QStringLiteral("TCP") : QStringLiteral("UDP");
}

int runProbe(const QString& mask, const bool exact) {
    gpd::platform::ProcessMonitorWin processMonitor;
    gpd::platform::ConnectionScannerWin scanner;
    gpd::platform::InterfaceInspectorWin interfaceInspector;
    gpd::platform::RouteResolverWin resolver;
    gpd::core::UdpFlowAggregator udpFlows;

    const auto interfaces = interfaceInspector.listInterfaces();
    QHash<std::uint32_t, gpd::core::NetworkInterfaceInfo> interfacesByIndex;
    for (const auto& iface : interfaces) {
        interfacesByIndex.insert(iface.ifIndex, iface);
    }

    int matched = 0;
    int rawTotal = 0;
    int enrichedTotal = 0;
    for (const auto& process : processMonitor.listProcesses()) {
        const bool ok = exact ? process.name.compare(mask, Qt::CaseInsensitive) == 0 : process.name.contains(mask, Qt::CaseInsensitive);
        if (!ok) {
            continue;
        }
        ++matched;
        const auto raw = scanner.listConnectionsForPid(process.pid);
        const auto enriched = gpd::core::ConnectionEnricher::enrich(raw, interfacesByIndex, resolver, udpFlows, true);
        rawTotal += raw.size();
        enrichedTotal += enriched.size();
        std::cout << "PROCESS " << process.name.toStdString() << " pid=" << process.pid << " raw=" << raw.size()
                  << " enriched=" << enriched.size() << '\n';
        for (const auto& connection : enriched) {
            std::cout << "  " << protocolText(connection.protocol).toStdString() << ' ' << connection.localAddress.toStdString() << ':'
                      << connection.localPort << " -> " << connection.remoteAddress.toStdString() << ':' << connection.remotePort
                      << " if=" << connection.routedThroughInterfaceName.toStdString() << " verdict=" << connection.perRowVerdict.toStdString()
                      << '\n';
        }
    }

    std::cout << "SUMMARY matched=" << matched << " raw=" << rawTotal << " enriched=" << enrichedTotal << '\n';
    return matched > 0 ? 0 : 2;
}

int runEtwProbe(QCoreApplication& app, const int seconds) {
    gpd::platform::EtwNetworkTap tap;
    QUdpSocket udp;
    int batches = 0;
    int events = 0;
    QObject::connect(&tap, &gpd::platform::EtwNetworkTap::udpEventBatch, &app, [&](const QVector<gpd::core::UdpFlowEvent>& batch) {
        ++batches;
        events += batch.size();
        std::cout << "ETW_BATCH size=" << batch.size() << '\n';
        for (int i = 0; i < batch.size() && i < 8; ++i) {
            const auto& event = batch[i];
            std::cout << "  pid=" << event.pid << ' ' << event.localAddress.toStdString() << ':' << event.localPort << " -> "
                      << event.remoteAddress.toStdString() << ':' << event.remotePort << " send=" << event.isSend << " bytes=" << event.sizeBytes
                      << '\n';
        }
    });
    QObject::connect(&tap, &gpd::platform::EtwNetworkTap::statusChanged, &app, [&](const gpd::platform::EtwStatus status) {
        std::cout << "ETW_STATUS " << static_cast<int>(status) << '\n';
        if (status == gpd::platform::EtwStatus::Failed) {
            const auto error = tap.lastError();
            std::cout << "ETW_ERROR code=" << error.lastError << " message=" << error.message.toStdString() << '\n';
        }
    });

    tap.start();
    QTimer trafficTimer;
    QObject::connect(&trafficTimer, &QTimer::timeout, &app, [&]() {
        const QByteArray payload("routelens-etw-probe");
        udp.writeDatagram(payload, QHostAddress(QStringLiteral("1.1.1.1")), 53);
    });
    trafficTimer.start(200);
    QTimer::singleShot(seconds * 1000, &app, [&]() {
        trafficTimer.stop();
        tap.stop();
        app.quit();
    });
    app.exec();
    udp.close();
    std::cout << "ETW_SUMMARY batches=" << batches << " events=" << events << '\n';
    return events > 0 ? 0 : 3;
}

} // namespace

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    const auto args = app.arguments();
    if (args.size() >= 3 && args[1] == QStringLiteral("--probe-process")) {
        return runProbe(args[2], true);
    }
    if (args.size() >= 3 && args[1] == QStringLiteral("--probe-name-contains")) {
        return runProbe(args[2], false);
    }
    if (args.size() >= 2 && args[1] == QStringLiteral("--probe-etw")) {
        const int seconds = args.size() >= 3 ? args[2].toInt() : 10;
        return runEtwProbe(app, seconds <= 0 ? 10 : seconds);
    }

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

    {
        gpd::core::UdpFlowAggregator aggregator;
        gpd::core::UdpEndpointKey key;
        key.pid = 100;
        key.localAddress = QStringLiteral("10.0.0.2");
        key.localPort = 27015;
        expectTrue(aggregator.endpointsFor(key).isEmpty());

        gpd::core::UdpFlowEvent event;
        event.pid = 100;
        event.localAddress = key.localAddress;
        event.localPort = key.localPort;
        event.remoteAddress = QStringLiteral("155.133.248.1");
        event.remotePort = 27036;
        event.isSend = true;
        event.sizeBytes = 120;
        event.timestampMs = QDateTime::currentMSecsSinceEpoch();
        aggregator.ingestBatch({event});

        auto endpoints = aggregator.endpointsFor(key);
        expectTrue(endpoints.size() == 1);
        expectTrue(endpoints[0].sentPackets == 1);
        expectTrue(endpoints[0].sentBytes == 120);

        event.sizeBytes = 50;
        event.timestampMs += 20;
        aggregator.ingestBatch({event});
        endpoints = aggregator.endpointsFor(key);
        expectTrue(endpoints[0].sentPackets == 2);
        expectTrue(endpoints[0].sentBytes == 170);

        aggregator.pruneOlderThan(QDateTime::currentMSecsSinceEpoch() + 1000);
        expectTrue(aggregator.endpointsFor(key).isEmpty());
    }

    return failures == 0 ? 0 : 1;
}
