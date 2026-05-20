#include "ui/MainWindow.h"

#include "core/Models.h"
#include "platform/windows/ConnectionScannerWin.h"
#include "platform/windows/ProcessMonitorWin.h"
#include "ui/VerdictBadge.h"

#include <QComboBox>
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
    , connectionScanner_(std::make_unique<gpd::platform::ConnectionScannerWin>()) {
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

    auto* footer = makeQtOwned<QLabel>(tr("Select a process and start monitoring to view live TCP/UDP connections."), central);
    footer->setWordWrap(true);
    root->addWidget(footer);

    setCentralWidget(central);

    refreshTimer_ = makeQtOwned<QTimer>(this);
    refreshTimer_->setInterval(1500);

    connect(refreshButton_, &QPushButton::clicked, this, &MainWindow::refreshProcesses);
    connect(startStopButton_, &QPushButton::clicked, this, &MainWindow::updateMonitoringState);
    connect(refreshTimer_, &QTimer::timeout, this, &MainWindow::refreshConnections);
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
    const auto selectedPid = processCombo_->currentData().toUInt();
    connectionTable_->setRowCount(0);
    if (selectedPid == 0) {
        return;
    }

    const auto connections = connectionScanner_->listConnectionsForPid(selectedPid);
    connectionTable_->setRowCount(connections.size());
    for (int row = 0; row < connections.size(); ++row) {
        fillConnectionRow(row, connections[row]);
    }
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
    setItem(8, QStringLiteral("%1:%2").arg(connection.localAddress).arg(connection.localPort));
    setItem(9, QStringLiteral("Pending"));
}

} // namespace gpd::ui
