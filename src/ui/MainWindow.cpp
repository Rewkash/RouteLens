#include "ui/MainWindow.h"

#include "core/ConnectionEnricher.h"
#include "core/InterfaceClassifier.h"
#include "core/Models.h"
#include "core/RouteClassifier.h"
#include "platform/windows/ConnectionScannerWin.h"
#include "platform/windows/InterfaceInspectorWin.h"
#include "platform/windows/ProcessMonitorWin.h"
#include "platform/windows/RouteResolverWin.h"
#include "ui/InterfacesPanel.h"
#include "ui/KindIcon.h"
#include "ui/VerdictBadge.h"

#include <QComboBox>
#include <QDateTime>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
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
    , routeResolver_(std::make_unique<gpd::platform::RouteResolverWin>()) {
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
    root->addWidget(topBar);

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
    root->addWidget(connectionTable_, 1);

    interfacesPanel_ = makeQtOwned<InterfacesPanel>(central);
    root->addWidget(interfacesPanel_);

    auto* footer = makeQtOwned<QLabel>(tr("Select a process and start monitoring to view live TCP/UDP connections."), central);
    footer->setWordWrap(true);
    root->addWidget(footer);

    setCentralWidget(central);

    refreshTimer_ = makeQtOwned<QTimer>(this);
    refreshTimer_->setInterval(1500);

    connect(refreshButton_, &QPushButton::clicked, this, &MainWindow::refreshProcesses);
    connect(startStopButton_, &QPushButton::clicked, this, &MainWindow::updateMonitoringState);
    connect(refreshTimer_, &QTimer::timeout, this, &MainWindow::refreshConnections);
    connect(&refreshWatcher_, &QFutureWatcher<RefreshResult>::finished, this, [this]() {
        refreshInFlight_ = false;
        applyRefreshResult(refreshWatcher_.result());
    });
    connect(processCombo_, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](int) {
        if (!monitoring_) {
            refreshConnections();
        }
    });

    refreshProcesses();
    refreshConnections();
}

MainWindow::~MainWindow() = default;

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

    refreshWatcher_.setFuture(QtConcurrent::run([selectedPid, interfacesByIndex, interfaces, scanner, resolver]() {
        RefreshResult result;
        result.interfaces = interfaces;
        result.interfacesByIndex = interfacesByIndex;
        const auto connections = scanner->listConnectionsForPid(selectedPid);
        result.connections = gpd::core::ConnectionEnricher::enrich(connections, interfacesByIndex, *resolver);
        result.verdict = gpd::core::RouteClassifier::classify(result.connections);
        return result;
    }));
}

void MainWindow::applyRefreshResult(const RefreshResult& result) {
    connectionTable_->setRowCount(result.connections.size());
    for (int row = 0; row < result.connections.size(); ++row) {
        fillConnectionRow(row, result.connections[row]);
    }

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
        refreshConnections();
        return;
    }

    refreshTimer_->stop();
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
    setItem(3, QStringLiteral("-"));
    setItem(4, QStringLiteral("-"));
    setItem(5, QStringLiteral("-"));
    setItem(6, QStringLiteral("-"));
    setItem(7, QStringLiteral("-"));
    auto* interfaceItem = makeQtOwned<QTableWidgetItem>(connection.routedThroughInterfaceName.isEmpty() ? QStringLiteral("-") : connection.routedThroughInterfaceName);
    interfaceItem->setIcon(KindIcon::make(connection.routedThroughKind));
    if (!connection.routedThroughDescription.isEmpty()) {
        interfaceItem->setToolTip(connection.routedThroughDescription);
    }
    connectionTable_->setItem(row, 8, interfaceItem);
    setItem(9, connection.perRowVerdict);
}

} // namespace gpd::ui
