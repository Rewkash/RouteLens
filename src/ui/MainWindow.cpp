#include "ui/MainWindow.h"

#include "core/ConnectionEnricher.h"
#include "core/GeoIpResolver.h"
#include "core/InterfaceClassifier.h"
#include "core/Models.h"
#include "core/PingScheduler.h"
#include "core/RouteClassifier.h"
#include "core/UdpFlowAggregator.h"
#include "platform/windows/ConnectionScannerWin.h"
#include "platform/windows/EtwNetworkTap.h"
#include "platform/windows/InterfaceInspectorWin.h"
#include "platform/windows/PingProbeWin.h"
#include "platform/windows/ProcessMonitorWin.h"
#include "platform/windows/RouteResolverWin.h"
#include "platform/windows/TcpPingProbeWin.h"
#include "ui/InterfacesPanel.h"
#include "ui/KindIcon.h"
#include "ui/VerdictBadge.h"

#include <QComboBox>
#include <QDateTime>
#include <QDesktopServices>
#include <QDialog>
#include <QColor>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMenuBar>
#include <QDebug>
#include <QPushButton>
#include <QSettings>
#include <QUrl>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>
#include <QVariant>
#include <QWidget>

#include <QtConcurrent>

#include <cstdint>
#include <memory>
#include <utility>

namespace {

template <typename T, typename... Args>
T* makeQtOwned(Args&&... args) {
    return std::make_unique<T>(std::forward<Args>(args)...).release();
}

} // namespace

namespace gpd::ui {

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , processMonitor_(std::make_unique<gpd::platform::ProcessMonitorWin>())
    , connectionScanner_(std::make_unique<gpd::platform::ConnectionScannerWin>())
    , interfaceInspector_(std::make_unique<gpd::platform::InterfaceInspectorWin>())
    , routeResolver_(std::make_unique<gpd::platform::RouteResolverWin>())
    , etwTap_(std::make_unique<gpd::platform::EtwNetworkTap>())
    , udpFlows_(std::make_unique<gpd::core::UdpFlowAggregator>())
    , geoIp_(std::make_unique<gpd::core::GeoIpResolver>())
    , pingProbe_(std::make_unique<gpd::platform::PingProbeWin>())
    , tcpPingProbe_(std::make_unique<gpd::platform::TcpPingProbeWin>())
    , pingScheduler_(std::make_unique<gpd::core::PingScheduler>(pingProbe_.get(), tcpPingProbe_.get())) {
    buildUi();
}

void MainWindow::buildUi() {
    setWindowTitle(tr("RouteLens"));
    setMinimumSize(1100, 720);

    auto* central = makeQtOwned<QWidget>(this);
    auto* root = makeQtOwned<QVBoxLayout>(central);
    root->setContentsMargins(18, 18, 18, 18);
    root->setSpacing(14);

    auto* topBar = makeQtOwned<QWidget>(central);
    auto* topLayout = makeQtOwned<QHBoxLayout>(topBar);
    topLayout->setContentsMargins(0, 0, 0, 0);

    topLayout->addWidget(makeQtOwned<QLabel>(tr("Game process:"), topBar));
    processCombo_ = makeQtOwned<QComboBox>(topBar);
    processCombo_->setMinimumWidth(360);
    topLayout->addWidget(processCombo_, 1);

    refreshButton_ = makeQtOwned<QPushButton>(tr("Refresh"), topBar);
    topLayout->addWidget(refreshButton_);

    startStopButton_ = makeQtOwned<QPushButton>(tr("Start monitoring"), topBar);
    topLayout->addWidget(startStopButton_);

    etwStatusLabel_ = makeQtOwned<QLabel>(tr("○ ETW: off"), topBar);
    topLayout->addWidget(etwStatusLabel_);
    geoStatusLabel_ = makeQtOwned<QLabel>(tr("○ GeoIP: missing"), topBar);
    topLayout->addWidget(geoStatusLabel_);
    root->addWidget(topBar);

    auto* settingsMenu = menuBar()->addMenu(tr("Settings"));
    configureGeoIpAction_ = settingsMenu->addAction(tr("Configure GeoIP databases..."));

    verdictBadge_ = makeQtOwned<VerdictBadge>(central);
    verdictBadge_->setVerdict({gpd::core::RouteVerdict::Unknown, 0, tr("Monitoring is not started yet.")});
    root->addWidget(verdictBadge_);

    connectionTable_ = makeQtOwned<QTableWidget>(0, 10, central);
    connectionTable_->setHorizontalHeaderLabels({
        tr("Remote IP"),
        tr("Port"),
        tr("Protocol"),
        tr("Country"),
        tr("ASN"),
        tr("RTT avg"),
        tr("Jitter"),
        tr("Loss %"),
        tr("Interface"),
        tr("Verdict"),
    });
    connectionTable_->horizontalHeader()->setStretchLastSection(true);
    connectionTable_->verticalHeader()->setVisible(false);
    connectionTable_->setAlternatingRowColors(true);
    connectionTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    connectionTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    connectionTable_->setSortingEnabled(true);
    root->addWidget(connectionTable_, 1);

    interfacesPanel_ = makeQtOwned<InterfacesPanel>(central);
    root->addWidget(interfacesPanel_);

    auto* footer = makeQtOwned<QLabel>(tr("Select a process and start monitoring to view live TCP/UDP connections."), central);
    footer->setWordWrap(true);
    root->addWidget(footer);

    setCentralWidget(central);

    refreshTimer_ = makeQtOwned<QTimer>(this);
    refreshTimer_->setInterval(1500);

    pruneTimer_ = makeQtOwned<QTimer>(this);
    pruneTimer_->setInterval(10000);

    connect(refreshButton_, &QPushButton::clicked, this, &MainWindow::refreshProcesses);
    connect(startStopButton_, &QPushButton::clicked, this, &MainWindow::updateMonitoringState);
    connect(configureGeoIpAction_, &QAction::triggered, this, &MainWindow::configureGeoIp);
    connect(refreshTimer_, &QTimer::timeout, this, &MainWindow::refreshConnections);
    connect(pruneTimer_, &QTimer::timeout, this, [this]() {
        udpFlows_->pruneOlderThan(QDateTime::currentMSecsSinceEpoch() - 30000);
    });
    connect(etwTap_.get(), &gpd::platform::EtwNetworkTap::udpEventBatch, this, [this](const QVector<gpd::core::UdpFlowEvent>& events) {
        qInfo() << "ETW UDP batch" << events.size();
        udpFlows_->ingestBatch(events);
    }, Qt::QueuedConnection);
    connect(etwTap_.get(), &gpd::platform::EtwNetworkTap::statusChanged, this, [this](const gpd::platform::EtwStatus status) {
        switch (status) {
        case gpd::platform::EtwStatus::Running:
            etwStatusLabel_->setText(QStringLiteral("● ETW: running"));
            etwStatusLabel_->setStyleSheet(QStringLiteral("QLabel { color: #37b24d; font-weight: 600; }"));
            break;
        case gpd::platform::EtwStatus::Failed:
            etwStatusLabel_->setText(QStringLiteral("● ETW: failed"));
            etwStatusLabel_->setStyleSheet(QStringLiteral("QLabel { color: #f03e3e; font-weight: 600; }"));
            etwStatusLabel_->setToolTip(etwTap_->lastError().message);
            break;
        case gpd::platform::EtwStatus::Starting:
            etwStatusLabel_->setText(QStringLiteral("○ ETW: starting"));
            etwStatusLabel_->setStyleSheet(QStringLiteral("QLabel { color: #fab005; font-weight: 600; }"));
            break;
        case gpd::platform::EtwStatus::Stopped:
            etwStatusLabel_->setText(QStringLiteral("○ ETW: off"));
            etwStatusLabel_->setStyleSheet(QString());
            break;
        }
    });
    connect(geoIp_.get(), &gpd::core::GeoIpResolver::statusChanged, this, [this](const bool ready) {
        geoStatusLabel_->setText(ready ? QStringLiteral("● GeoIP: ready") : QStringLiteral("○ GeoIP: missing"));
        geoStatusLabel_->setStyleSheet(ready ? QStringLiteral("QLabel { color: #37b24d; font-weight: 600; }") : QString());
    });
    connect(&refreshWatcher_, &QFutureWatcher<RefreshResult>::finished, this, [this]() {
        refreshInFlight_ = false;
        applyRefreshResult(refreshWatcher_.result());
    });
    connect(connectionTable_->horizontalHeader(), &QHeaderView::sortIndicatorChanged, this, [this](const int logicalIndex, const Qt::SortOrder order) {
        sortColumn_ = logicalIndex;
        sortOrder_ = order;
        persistTableSortState();
    });
    connect(processCombo_, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](int) {
        if (!monitoring_) {
            refreshConnections();
        }
    });

    refreshProcesses();
    restoreTableSortState();
    const QString geoDir = gpd::core::GeoIpResolver::defaultGeoDirectory();
    geoIp_->open(geoDir + QStringLiteral("/GeoLite2-Country.mmdb"), geoDir + QStringLiteral("/GeoLite2-ASN.mmdb"));
    refreshConnections();
}

MainWindow::~MainWindow() {
    if (etwTap_) {
        etwTap_->stop();
    }
    if (pingScheduler_) {
        pingScheduler_->stop();
    }
    if (pingProbe_) {
        pingProbe_->stop();
    }
    if (tcpPingProbe_) {
        tcpPingProbe_->stop();
    }
}

void MainWindow::refreshProcesses() {
    updateCachedInterfaces(true);
    const auto processes = processMonitor_->listProcesses();
    const auto activeCounts = connectionScanner_->activePidConnectionCounts();
    const auto currentPid = processCombo_->currentData().toUInt();

    processCombo_->blockSignals(true);
    processCombo_->clear();
    for (const auto& process : processes) {
        const int count = activeCounts.value(process.pid, 0);
        if (count <= 0) {
            continue;
        }
        processCombo_->addItem(
            QStringLiteral("%1 (%2) - %3").arg(process.name).arg(process.pid).arg(tr("connections: %1").arg(count)),
            QVariant::fromValue(process.pid));
    }

    int indexToSelect = -1;
    if (currentPid != 0) {
        indexToSelect = processCombo_->findData(QVariant::fromValue(currentPid));
    }
    if (indexToSelect >= 0) {
        processCombo_->setCurrentIndex(indexToSelect);
    } else if (processCombo_->count() > 0) {
        processCombo_->setCurrentIndex(0);
    }
    processCombo_->blockSignals(false);

    const bool hasProcesses = processCombo_->count() > 0;
    processCombo_->setEnabled(hasProcesses);
    startStopButton_->setEnabled(hasProcesses);

    if (!hasProcesses) {
        processCombo_->addItem(tr("No processes with active sockets"), QVariant::fromValue(0U));
        processCombo_->setEnabled(false);
        startStopButton_->setEnabled(false);
    }
}

void MainWindow::refreshConnections() {
    if (refreshInFlight_) {
        return;
    }

    const auto selectedPid = processCombo_->currentData().toUInt();
    if (selectedPid == 0) {
        connectionTable_->setRowCount(0);
        return;
    }

    updateCachedInterfaces(false);

    refreshInFlight_ = true;
    const auto interfacesByIndex = cachedInterfacesByIndex_;
    const auto interfaces = cachedInterfaces_;
    const auto* scanner = connectionScanner_.get();
    const auto* resolver = routeResolver_.get();
    const auto* udpFlows = udpFlows_.get();
    const bool etwRunning = etwTap_->status() == gpd::platform::EtwStatus::Running;
    const bool geoReady = geoIp_->isReady();
    const auto pingSnapshot = pingScheduler_->snapshot();

    refreshWatcher_.setFuture(QtConcurrent::run([selectedPid, interfacesByIndex, interfaces, scanner, resolver, udpFlows, etwRunning, geoReady, pingSnapshot, this]() {
        RefreshResult result;
        result.selectedPid = selectedPid;
        result.interfaces = interfaces;
        result.interfacesByIndex = interfacesByIndex;
        result.etwRunning = etwRunning;
        result.geoReady = geoReady;
        const auto connections = scanner->listConnectionsForPid(selectedPid);
        result.rawConnectionCount = connections.size();
        result.connections = gpd::core::ConnectionEnricher::enrich(connections, interfacesByIndex, *resolver, *udpFlows, etwRunning);
        QStringList geoIps;
        QVector<gpd::core::TargetEndpoint> targets;
        for (const auto& connection : result.connections) {
            if (connection.hasPublicRemoteEndpoint) {
                geoIps.push_back(connection.remoteAddress);
                targets.push_back({connection.remoteAddress, connection.remotePort, connection.isPrivateDestination});
            }
        }
        QMetaObject::invokeMethod(this, [this, targets]() { pingScheduler_->updateTargets(targets); }, Qt::QueuedConnection);
        const auto geoMap = geoIp_->lookupBatch(geoIps);
        for (auto& connection : result.connections) {
            if (connection.hasPublicRemoteEndpoint) {
                connection.geoInfo = geoMap.value(connection.remoteAddress);
                connection.pingAggregate = pingSnapshot.value(connection.remoteAddress);
            }
        }
        result.verdict = gpd::core::RouteClassifier::classify(result.connections);
        return result;
    }));
}

void MainWindow::applyRefreshResult(const RefreshResult& result) {
    qInfo() << "RouteLens refresh pid" << result.selectedPid << "raw" << result.rawConnectionCount << "enriched" << result.connections.size()
            << "etw" << result.etwRunning;
    connectionTable_->setSortingEnabled(false);
    connectionTable_->setRowCount(result.connections.size());
    for (int row = 0; row < result.connections.size(); ++row) {
        fillConnectionRow(row, result.connections[row]);
    }
    connectionTable_->setSortingEnabled(true);
    connectionTable_->sortItems(sortColumn_, sortOrder_);

    verdictBadge_->setVerdict(result.verdict);
    interfacesPanel_->setInterfaces(result.interfaces);
}

void MainWindow::updateCachedInterfaces(const bool forceUpdate) {
    const auto nowMs = QDateTime::currentMSecsSinceEpoch();
    if (!forceUpdate && !cachedInterfaces_.isEmpty() && (nowMs - lastInterfaceRefreshMs_) < 5000) {
        return;
    }

    cachedInterfaces_ = interfaceInspector_->listInterfaces();
    cachedInterfacesByIndex_.clear();
    for (const auto& interfaceInfo : cachedInterfaces_) {
        cachedInterfacesByIndex_.insert(interfaceInfo.ifIndex, interfaceInfo);
    }
    lastInterfaceRefreshMs_ = nowMs;
    interfacesPanel_->setInterfaces(cachedInterfaces_);
}

void MainWindow::updateMonitoringState() {
    monitoring_ = !monitoring_;
    if (monitoring_) {
        startStopButton_->setText(tr("Stop"));
        refreshTimer_->start();
        verdictBadge_->setVerdict({gpd::core::RouteVerdict::Unknown, 5, tr("Connection scanning is active. Route verdict will arrive in later milestones.")});
        pingProbe_->start();
        tcpPingProbe_->start();
        pingScheduler_->start();
        const bool etwStarted = etwTap_->start();
        if (!etwStarted && etwTap_->status() == gpd::platform::EtwStatus::Failed) {
            etwStatusLabel_->setToolTip(etwTap_->lastError().message);
        }
        pruneTimer_->start();
        refreshConnections();
        return;
    }

    refreshTimer_->stop();
    pruneTimer_->stop();
    etwTap_->stop();
    pingScheduler_->stop();
    pingProbe_->stop();
    tcpPingProbe_->stop();
    startStopButton_->setText(tr("Start monitoring"));
    verdictBadge_->setVerdict({gpd::core::RouteVerdict::Unknown, 0, tr("Monitoring is stopped.")});
}

void MainWindow::fillConnectionRow(const int row, const gpd::core::ConnectionInfo& connection) {
    const auto setItem = [&](const int column, const QString& text) {
        auto* item = makeQtOwned<QTableWidgetItem>(text);
        connectionTable_->setItem(row, column, item);
    };

    setItem(0, connection.remoteAddress);
    setItem(1, connection.remotePort == 0 ? QStringLiteral("-") : QString::number(connection.remotePort));
    setItem(2, gpd::core::protocolToString(connection.protocol));
    QString countryText = QStringLiteral("-");
    QString asnText = QStringLiteral("-");
    if (!connection.hasPublicRemoteEndpoint) {
        countryText = QStringLiteral("-");
    } else if (connection.geoInfo.isPrivate) {
        countryText = QStringLiteral("Private");
        asnText = QStringLiteral("—");
    } else if (!connection.geoInfo.resolved) {
        countryText = geoIp_->isReady() ? QStringLiteral("?") : QStringLiteral("-");
        asnText = geoIp_->isReady() ? QStringLiteral("?") : QStringLiteral("-");
    } else {
        countryText = connection.geoInfo.countryIsoCode;
        if (!connection.geoInfo.countryName.isEmpty()) {
            countryText += QStringLiteral(" — ") + connection.geoInfo.countryName;
        }
        asnText = connection.geoInfo.asnNumber;
        if (!connection.geoInfo.asnOrganization.isEmpty()) {
            asnText += QStringLiteral(" (") + connection.geoInfo.asnOrganization + QStringLiteral(")");
        }
    }
    setItem(3, countryText);
    setItem(4, asnText);

    QString rttText = QStringLiteral("…");
    QString jitterText = QStringLiteral("…");
    QString lossText = QStringLiteral("…");
    if (!connection.hasPublicRemoteEndpoint) {
        rttText = QStringLiteral("-");
        jitterText = QStringLiteral("-");
        lossText = QStringLiteral("-");
    } else if (connection.pingAggregate.unreachable) {
        rttText = QStringLiteral("unreach");
        jitterText = QStringLiteral("—");
        lossText = QStringLiteral("100%");
    } else if (connection.pingAggregate.samplesInWindow >= 3 && connection.pingAggregate.rttAvgMs >= 0) {
        rttText = QStringLiteral("%1 ms").arg(connection.pingAggregate.rttAvgMs);
        jitterText = QStringLiteral("%1 ms").arg(QString::number(connection.pingAggregate.jitterMs, 'f', 1));
        lossText = QStringLiteral("%1%").arg(QString::number(connection.pingAggregate.lossPercent, 'f', 1));
    }
    setItem(5, rttText);
    setItem(6, jitterText);
    auto* lossItem = makeQtOwned<QTableWidgetItem>(lossText);
    if (connection.pingAggregate.lossPercent <= 0.0) {
        lossItem->setForeground(QColor(QStringLiteral("#2f9e44")));
    } else if (connection.pingAggregate.lossPercent <= 5.0) {
        lossItem->setForeground(QColor(QStringLiteral("#f08c00")));
    } else {
        lossItem->setForeground(QColor(QStringLiteral("#e03131")));
    }
    connectionTable_->setItem(row, 7, lossItem);
    if (connection.pingAggregate.icmpBlocked) {
        auto* rttItem = connectionTable_->item(row, 5);
        if (rttItem != nullptr) {
            rttItem->setToolTip(QStringLiteral("ICMP blocked, using TCP fallback"));
        }
    }
    auto* interfaceItem = makeQtOwned<QTableWidgetItem>(connection.routedThroughInterfaceName.isEmpty() ? QStringLiteral("-") : connection.routedThroughInterfaceName);
    interfaceItem->setIcon(KindIcon::make(connection.routedThroughKind));
    if (!connection.routedThroughDescription.isEmpty()) {
        interfaceItem->setToolTip(connection.routedThroughDescription);
    }
    connectionTable_->setItem(row, 8, interfaceItem);
    setItem(9, connection.perRowVerdict);
}

void MainWindow::configureGeoIp() {
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Configure GeoIP databases"));
    auto* layout = makeQtOwned<QVBoxLayout>(&dialog);
    const QString geoDir = gpd::core::GeoIpResolver::defaultGeoDirectory();
    auto* label = makeQtOwned<QLabel>(
        tr("Place GeoLite2-Country.mmdb and GeoLite2-ASN.mmdb in:\n%1\n\nGet free databases from https://www.maxmind.com/en/geolite2/signup")
            .arg(geoDir),
        &dialog);
    label->setWordWrap(true);
    layout->addWidget(label);
    auto* openButton = makeQtOwned<QPushButton>(tr("Open data folder"), &dialog);
    auto* reloadButton = makeQtOwned<QPushButton>(tr("Reload databases"), &dialog);
    auto* closeButton = makeQtOwned<QPushButton>(tr("Close"), &dialog);
    layout->addWidget(openButton);
    layout->addWidget(reloadButton);
    layout->addWidget(closeButton);
    connect(openButton, &QPushButton::clicked, &dialog, [geoDir]() { QDesktopServices::openUrl(QUrl::fromLocalFile(geoDir)); });
    connect(reloadButton, &QPushButton::clicked, &dialog, [this, geoDir]() {
        geoIp_->open(geoDir + QStringLiteral("/GeoLite2-Country.mmdb"), geoDir + QStringLiteral("/GeoLite2-ASN.mmdb"));
    });
    connect(closeButton, &QPushButton::clicked, &dialog, &QDialog::accept);
    dialog.exec();
}

void MainWindow::restoreTableSortState() {
    QSettings settings;
    sortColumn_ = settings.value(QStringLiteral("ui/sortColumn"), 0).toInt();
    sortOrder_ = settings.value(QStringLiteral("ui/sortOrder"), static_cast<int>(Qt::AscendingOrder)).toInt() == static_cast<int>(Qt::DescendingOrder)
                     ? Qt::DescendingOrder
                     : Qt::AscendingOrder;
    connectionTable_->horizontalHeader()->setSortIndicator(sortColumn_, sortOrder_);
}

void MainWindow::persistTableSortState() const {
    QSettings settings;
    settings.setValue(QStringLiteral("ui/sortColumn"), sortColumn_);
    settings.setValue(QStringLiteral("ui/sortOrder"), static_cast<int>(sortOrder_));
}

} // namespace gpd::ui
