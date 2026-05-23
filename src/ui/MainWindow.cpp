#include "ui/MainWindow.h"

#include "core/ConnectionEnricher.h"
#include "core/ClashApiClient.h"
#include "core/ClashConnectionMatcher.h"
#include "core/GeoIpResolver.h"
#include "core/InterfaceClassifier.h"
#include "core/Models.h"
#include "core/PingScheduler.h"
#include "core/diagnostic/DiagnosticEngine.h"
#include "core/diagnostic/DiagnosticTypes.h"
#include "core/RouteClassifier.h"
#include "core/TunnelCorrelator.h"
#include "core/TunnelProcessRegistry.h"
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
#include <QInputDialog>
#include <QLabel>
#include <QMenuBar>
#include <QDebug>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPushButton>
#include <QProgressBar>
#include <QRegularExpression>
#include <QSettings>
#include <QSet>
#include <QUrl>
#include <QTabWidget>
#include <QFileDialog>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QPlainTextEdit>
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

namespace {
constexpr double kMinExpectedUdpIntervalMs = 7.0;
constexpr double kMaxExpectedUdpIntervalMs = 40.0;
constexpr double kUdpBaseRttFactor = 4.0;
constexpr double kUdpQueueDelayFactor = 3.5;
constexpr double kUdpJitterAmplification = 4.0;
constexpr double kVpnTunnelRttFactor = 2.2;

QStringList runningProcessNamesLower() {
    QProcess process;
    process.start(QStringLiteral("tasklist"), {QStringLiteral("/FO"), QStringLiteral("CSV"), QStringLiteral("/NH")});
    if (!process.waitForFinished(3000)) {
        return {};
    }
    const QString output = QString::fromLocal8Bit(process.readAllStandardOutput());
    QStringList out;
    const auto lines = output.split(QChar('\n'), Qt::SkipEmptyParts);
    for (const auto& rawLine : lines) {
        const QString line = rawLine.trimmed();
        if (!line.startsWith(QLatin1Char('"'))) {
            continue;
        }
        const int secondQuote = line.indexOf(QLatin1Char('"'), 1);
        if (secondQuote <= 1) {
            continue;
        }
        const QString imageName = line.mid(1, secondQuote - 1).toLower();
        if (!imageName.isEmpty()) {
            out.push_back(imageName);
        }
    }
    return out;
}

QString detectLikelyOwnerProcess(const gpd::core::NetworkInterfaceInfo& info) {
    const QString f = info.friendlyName.toLower();
    const QString d = info.description.toLower();
    const QString a = info.adapterName.toLower();
    const QString blob = f + QStringLiteral(" ") + d + QStringLiteral(" ") + a;
    const QStringList processes = runningProcessNamesLower();

    const auto findExact = [&](const QStringList& candidates) -> QString {
        for (const auto& c : candidates) {
            if (processes.contains(c)) {
                return c;
            }
        }
        return {};
    };

    if (blob.contains(QStringLiteral("nekobox")) || blob.contains(QStringLiteral("sing-tun")) || blob.contains(QStringLiteral("sing_tun"))) {
        const QString owner = findExact({QStringLiteral("nekobox.exe"), QStringLiteral("nekobox_core.exe"), QStringLiteral("sing-box.exe"),
                                         QStringLiteral("singbox.exe")});
        if (!owner.isEmpty()) {
            return owner;
        }
    }
    if (blob.contains(QStringLiteral("tailscale")) || blob.contains(QStringLiteral("tailscaled"))) {
        const QString owner = findExact({QStringLiteral("tailscaled.exe"), QStringLiteral("tailscale.exe")});
        if (!owner.isEmpty()) {
            return owner;
        }
    }

    QStringList tokens = blob.split(QRegularExpression(QStringLiteral("[^a-z0-9_\\-.]+")), Qt::SkipEmptyParts);
    tokens.removeDuplicates();
    for (const auto& token : tokens) {
        if (token.size() < 5) {
            continue;
        }
        for (const auto& p : processes) {
            if (p.contains(token)) {
                return p;
            }
        }
    }
    return {};
}
}

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , processMonitor_(std::make_unique<gpd::platform::ProcessMonitorWin>())
    , connectionScanner_(std::make_unique<gpd::platform::ConnectionScannerWin>())
    , interfaceInspector_(std::make_unique<gpd::platform::InterfaceInspectorWin>())
    , routeResolver_(std::make_unique<gpd::platform::RouteResolverWin>())
    , etwTap_(std::make_unique<gpd::platform::EtwNetworkTap>())
    , clashApi_(std::make_unique<gpd::core::ClashApiClient>(this))
    , clashMatcher_(std::make_unique<gpd::core::ClashConnectionMatcher>())
    , udpFlows_(std::make_unique<gpd::core::UdpFlowAggregator>())
    , geoIp_(std::make_unique<gpd::core::GeoIpResolver>())
    , pingProbe_(std::make_unique<gpd::platform::PingProbeWin>())
    , tcpPingProbe_(std::make_unique<gpd::platform::TcpPingProbeWin>())
    , pingScheduler_(std::make_unique<gpd::core::PingScheduler>(pingProbe_.get(), tcpPingProbe_.get()))
    , tunnelCorrelator_(std::make_unique<gpd::core::TunnelCorrelator>(5000))
    , diagnosticEngine_(std::make_unique<gpd::core::DiagnosticEngine>(pingScheduler_.get(), this)) {
    diagnosticEngine_->setUdpFlowAggregator(udpFlows_.get());
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

    topLayout->addWidget(makeQtOwned<QLabel>(tr("Игровой процесс:"), topBar));
    processCombo_ = makeQtOwned<QComboBox>(topBar);
    processCombo_->setMinimumWidth(360);
    topLayout->addWidget(processCombo_, 1);

    refreshButton_ = makeQtOwned<QPushButton>(tr("Обновить"), topBar);
    topLayout->addWidget(refreshButton_);

    startStopButton_ = makeQtOwned<QPushButton>(tr("Запустить мониторинг"), topBar);
    topLayout->addWidget(startStopButton_);

    etwStatusLabel_ = makeQtOwned<QLabel>(tr("○ ETW: выкл"), topBar);
    topLayout->addWidget(etwStatusLabel_);
    geoStatusLabel_ = makeQtOwned<QLabel>(tr("○ GeoIP: отсутствует"), topBar);
    topLayout->addWidget(geoStatusLabel_);
    clashStatusLabel_ = makeQtOwned<QLabel>(tr("○ Clash API: выкл"), topBar);
    topLayout->addWidget(clashStatusLabel_);
    root->addWidget(topBar);

    auto* settingsMenu = menuBar()->addMenu(tr("Настройки"));
    configureGeoIpAction_ = settingsMenu->addAction(tr("Настроить базы GeoIP..."));

    verdictBadge_ = makeQtOwned<VerdictBadge>(central);
    verdictBadge_->setVerdict({gpd::core::RouteVerdict::Unknown, 0, tr("Мониторинг еще не запущен.")});
    root->addWidget(verdictBadge_);

    auto* tabs = makeQtOwned<QTabWidget>(central);

    auto* monitorPage = makeQtOwned<QWidget>(tabs);
    auto* monitorLayout = makeQtOwned<QVBoxLayout>(monitorPage);
    monitorLayout->setContentsMargins(0, 0, 0, 0);

    connectionTable_ = makeQtOwned<QTableWidget>(0, 10, monitorPage);
    connectionTable_->setHorizontalHeaderLabels({
        tr("Удаленный IP"),
        tr("Порт"),
        tr("Протокол"),
        tr("Страна"),
        tr("ASN"),
        tr("RTT ср."),
        tr("Джиттер"),
        tr("Потери %"),
        tr("Интерфейс"),
        tr("Вердикт"),
    });
    connectionTable_->horizontalHeader()->setStretchLastSection(true);
    connectionTable_->verticalHeader()->setVisible(false);
    connectionTable_->setAlternatingRowColors(true);
    connectionTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    connectionTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    connectionTable_->setSortingEnabled(true);
    monitorLayout->addWidget(connectionTable_, 1);

    interfacesPanel_ = makeQtOwned<InterfacesPanel>(monitorPage);
    monitorLayout->addWidget(interfacesPanel_);

    tabs->addTab(monitorPage, tr("Соединения"));

    auto* diagnosticsPage = makeQtOwned<QWidget>(tabs);
    auto* diagnosticsLayout = makeQtOwned<QVBoxLayout>(diagnosticsPage);
    diagnosticsLayout->setContentsMargins(0, 0, 0, 0);
    runDiagnosticButton_ = makeQtOwned<QPushButton>(tr("Запустить полную диагностику"), diagnosticsPage);
    diagnosticsLayout->addWidget(runDiagnosticButton_);
    exportDiagnosticButton_ = makeQtOwned<QPushButton>(tr("Экспорт отчета"), diagnosticsPage);
    diagnosticsLayout->addWidget(exportDiagnosticButton_);
    diagnosticProgress_ = makeQtOwned<QProgressBar>(diagnosticsPage);
    diagnosticProgress_->setRange(0, 100);
    diagnosticProgress_->setValue(0);
    diagnosticsLayout->addWidget(diagnosticProgress_);
    diagnosticsView_ = makeQtOwned<QPlainTextEdit>(diagnosticsPage);
    diagnosticsView_->setReadOnly(true);
    diagnosticsLayout->addWidget(diagnosticsView_, 1);
    tabs->addTab(diagnosticsPage, tr("Диагностика"));

    root->addWidget(tabs, 1);

    auto* footer = makeQtOwned<QLabel>(tr("Выберите процесс и запустите мониторинг, чтобы видеть живые TCP/UDP соединения."), central);
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
        const qint64 now = QDateTime::currentMSecsSinceEpoch();
        udpFlows_->pruneOlderThan(now - 30000);
        tunnelCorrelator_->prune(now - 10000);
    });
    connect(etwTap_.get(), &gpd::platform::EtwNetworkTap::udpEventBatch, this, [this](const QVector<gpd::core::UdpFlowEvent>& events) {
        qInfo() << "ETW UDP batch" << events.size();
        udpFlows_->ingestBatch(events);
        routeToTunnelCorrelator(events);
    }, Qt::QueuedConnection);
    connect(etwTap_.get(), &gpd::platform::EtwNetworkTap::statusChanged, this, [this](const gpd::platform::EtwStatus status) {
        switch (status) {
        case gpd::platform::EtwStatus::Running:
            etwStatusLabel_->setText(QStringLiteral("● ETW: работает"));
            etwStatusLabel_->setStyleSheet(QStringLiteral("QLabel { color: #37b24d; font-weight: 600; }"));
            break;
        case gpd::platform::EtwStatus::Failed:
            etwStatusLabel_->setText(QStringLiteral("● ETW: ошибка"));
            etwStatusLabel_->setStyleSheet(QStringLiteral("QLabel { color: #f03e3e; font-weight: 600; }"));
            etwStatusLabel_->setToolTip(etwTap_->lastError().message);
            break;
        case gpd::platform::EtwStatus::Starting:
            etwStatusLabel_->setText(QStringLiteral("○ ETW: запуск"));
            etwStatusLabel_->setStyleSheet(QStringLiteral("QLabel { color: #fab005; font-weight: 600; }"));
            break;
        case gpd::platform::EtwStatus::Stopped:
            etwStatusLabel_->setText(QStringLiteral("○ ETW: выкл"));
            etwStatusLabel_->setStyleSheet(QString());
            break;
        }
    });
    connect(geoIp_.get(), &gpd::core::GeoIpResolver::statusChanged, this, [this](const bool ready) {
        geoStatusLabel_->setText(ready ? QStringLiteral("● GeoIP: готово") : QStringLiteral("○ GeoIP: отсутствует"));
        geoStatusLabel_->setStyleSheet(ready ? QStringLiteral("QLabel { color: #37b24d; font-weight: 600; }") : QString());
    });
    connect(clashApi_.get(), &gpd::core::ClashApiClient::snapshotUpdated, this, [this](const gpd::core::ClashApiSnapshot& snap) {
        clashMatcher_->rebuildIndex(snap);
        clashStatusLabel_->setText(QStringLiteral("● Clash API: подключено (%1)").arg(snap.connections.size()));
        clashStatusLabel_->setStyleSheet(QStringLiteral("QLabel { color: #37b24d; font-weight: 600; }"));
    });
    connect(clashApi_.get(), &gpd::core::ClashApiClient::statusChanged, this, [this](const gpd::core::ClashApiStatus status) {
        switch (status) {
        case gpd::core::ClashApiStatus::Connected:
            clashStatusLabel_->setText(QStringLiteral("● Clash API: подключено"));
            clashStatusLabel_->setStyleSheet(QStringLiteral("QLabel { color: #37b24d; font-weight: 600; }"));
            break;
        case gpd::core::ClashApiStatus::Disabled:
            clashStatusLabel_->setText(QStringLiteral("○ Clash API: выкл"));
            clashStatusLabel_->setStyleSheet(QString());
            break;
        case gpd::core::ClashApiStatus::Probing:
        case gpd::core::ClashApiStatus::Connecting:
            clashStatusLabel_->setText(QStringLiteral("○ Clash API: подключение"));
            clashStatusLabel_->setStyleSheet(QStringLiteral("QLabel { color: #fab005; font-weight: 600; }"));
            break;
        case gpd::core::ClashApiStatus::AuthFailed:
            clashStatusLabel_->setText(QStringLiteral("● Clash API: ошибка авторизации"));
            clashStatusLabel_->setStyleSheet(QStringLiteral("QLabel { color: #f03e3e; font-weight: 600; }"));
            break;
        case gpd::core::ClashApiStatus::Unreachable:
            clashStatusLabel_->setText(QStringLiteral("● Clash API: недоступно"));
            clashStatusLabel_->setStyleSheet(QStringLiteral("QLabel { color: #f03e3e; font-weight: 600; }"));
            break;
        case gpd::core::ClashApiStatus::InvalidResponse:
            clashStatusLabel_->setText(QStringLiteral("● Clash API: некорректный ответ"));
            clashStatusLabel_->setStyleSheet(QStringLiteral("QLabel { color: #f03e3e; font-weight: 600; }"));
            break;
        }
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
    connect(runDiagnosticButton_, &QPushButton::clicked, this, [this]() {
        const auto isUsableRemote = [](const gpd::core::ConnectionInfo& c) {
            if (!c.hasRemoteEndpoint || c.remotePort == 0 || c.remoteAddress.startsWith(QLatin1Char('('))) {
                return false;
            }
            if (c.remoteAddress == QStringLiteral("127.0.0.1") || c.remoteAddress == QStringLiteral("::1") ||
                c.remoteAddress == QStringLiteral("0.0.0.0") || c.remoteAddress == QStringLiteral("::")) {
                return false;
            }
            return true;
        };

        QVector<int> candidateIndices;
        QStringList candidateLabels;
        for (int i = 0; i < lastConnections_.size(); ++i) {
            const auto& c = lastConnections_[i];
            if (!isUsableRemote(c)) {
                continue;
            }
            const QString label = QStringLiteral("%1:%2 (%3)")
                                      .arg(c.remoteAddress)
                                      .arg(c.remotePort)
                                      .arg(c.protocol == gpd::core::TransportProtocol::Tcp ? QStringLiteral("TCP") : QStringLiteral("UDP"));
            if (candidateLabels.contains(label)) {
                continue;
            }
            candidateIndices.push_back(i);
            candidateLabels.push_back(label);
        }

        if (!candidateLabels.isEmpty()) {
            bool ok = false;
            const QString chosen = QInputDialog::getItem(this,
                                                         tr("Цель диагностики"),
                                                         tr("Выберите удаленный IP/порт для полной диагностики:"),
                                                         candidateLabels,
                                                         0,
                                                         false,
                                                         &ok);
            if (!ok || chosen.isEmpty()) {
                return;
            }
            const int selectedPos = candidateLabels.indexOf(chosen);
            if (selectedPos >= 0 && selectedPos < candidateIndices.size()) {
                const auto& selected = lastConnections_[candidateIndices[selectedPos]];
                diagnosticEngine_->setTarget(selected.remoteAddress, selected.remotePort, processCombo_->currentText(), selected.localAddress);
                diagnosticEngine_->setConnectionContext(selected);
                diagnosticEngine_->setTargetPid(selected.pid);
            }
        }

        diagnosticEngine_->runFullDiagnostic();
    });
    connect(exportDiagnosticButton_, &QPushButton::clicked, this, [this]() {
        const QString path = QFileDialog::getSaveFileName(this,
                                                          tr("Экспорт диагностического отчета"),
                                                          QStringLiteral("diagnostic_report.json"),
                                                          tr("Файлы JSON (*.json)"));
        if (path.isEmpty()) {
            return;
        }
        const auto report = diagnosticEngine_->currentReport();
        QJsonObject root;
        root.insert(QStringLiteral("targetIp"), report.targetIp);
        root.insert(QStringLiteral("targetPort"), report.targetPort);
        root.insert(QStringLiteral("targetProcessName"), report.targetProcessName);
        root.insert(QStringLiteral("overallStatus"), gpd::core::diagnosticStatusToString(report.overallStatus));
        root.insert(QStringLiteral("startedAtMs"), static_cast<qint64>(report.startedAtMs));
        root.insert(QStringLiteral("completedAtMs"), static_cast<qint64>(report.completedAtMs));
        QJsonArray sections;
        for (const auto& section : report.sections) {
            QJsonObject s;
            s.insert(QStringLiteral("id"), section.id);
            s.insert(QStringLiteral("title"), section.title);
            s.insert(QStringLiteral("status"), gpd::core::diagnosticStatusToString(section.overallStatus));
            QJsonArray findings;
            for (const auto& finding : section.findings) {
                QJsonObject f;
                f.insert(QStringLiteral("title"), finding.title);
                f.insert(QStringLiteral("metric"), finding.metric);
                f.insert(QStringLiteral("status"), gpd::core::diagnosticStatusToString(finding.status));
                f.insert(QStringLiteral("recommendation"), finding.recommendation);
                f.insert(QStringLiteral("timestampMs"), static_cast<qint64>(finding.timestampMs));
                findings.push_back(f);
            }
            s.insert(QStringLiteral("findings"), findings);
            sections.push_back(s);
        }
        root.insert(QStringLiteral("sections"), sections);
        QFile file(path);
        if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            const QJsonDocument doc(root);
            file.write(doc.toJson(QJsonDocument::Indented));
            file.close();
        }
    });
    connect(diagnosticEngine_.get(), &gpd::core::DiagnosticEngine::reportUpdated, this, &MainWindow::renderDiagnosticReport);
    connect(diagnosticEngine_.get(), &gpd::core::DiagnosticEngine::fullDiagnosticCompleted, this, &MainWindow::renderDiagnosticReport);
    connect(diagnosticEngine_.get(), &gpd::core::DiagnosticEngine::fullDiagnosticProgress, this, [this](const int p, const QString& step) {
        diagnosticProgress_->setValue(qBound(0, p, 100));
        diagnosticProgress_->setFormat(QStringLiteral("%1% - %2").arg(p).arg(step));
    });
    connect(interfacesPanel_, &InterfacesPanel::interfaceActivated, this, &MainWindow::showInterfaceDetails);

    refreshProcesses();
    restoreTableSortState();
    const QString geoDir = gpd::core::GeoIpResolver::defaultGeoDirectory();
    geoIp_->open(geoDir + QStringLiteral("/GeoLite2-Country.mmdb"), geoDir + QStringLiteral("/GeoLite2-ASN.mmdb"));
    QSettings clashSettings;
    if (clashSettings.value(QStringLiteral("clashApi/enabled"), true).toBool()) {
        const QUrl endpoint(clashSettings.value(QStringLiteral("clashApi/endpoint"), QStringLiteral("http://127.0.0.1:9090")).toString());
        const QString secret = clashSettings.value(QStringLiteral("clashApi/secret")).toString();
        clashApi_->configure(endpoint, secret);
        clashApi_->start(1000);
    }
    refreshConnections();
}

MainWindow::~MainWindow() {
    if (etwTap_) {
        etwTap_->stop();
    }
    if (clashApi_) {
        clashApi_->stop();
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
    QSet<std::uint32_t> aliveTunnels;
    for (const auto& process : processes) {
        if (!gpd::core::TunnelProcessRegistry::isKnownTunnel(process.name)) {
            continue;
        }
        aliveTunnels.insert(process.pid);
        tunnelCorrelator_->registerTunnelProcess(process.pid, process.name);
        registeredTunnelPids_.insert(process.pid, process.name.toLower());
    }
    for (auto it = registeredTunnelPids_.begin(); it != registeredTunnelPids_.end();) {
        if (!aliveTunnels.contains(it.key())) {
            tunnelCorrelator_->unregisterTunnelProcess(it.key());
            it = registeredTunnelPids_.erase(it);
        } else {
            ++it;
        }
    }

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
            QStringLiteral("%1 (%2) - %3").arg(process.name).arg(process.pid).arg(tr("соединений: %1").arg(count)),
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
        processCombo_->addItem(tr("Нет процессов с активными сокетами"), QVariant::fromValue(0U));
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
        for (auto& connection : result.connections) {
            if (connection.hasPublicRemoteEndpoint) {
                geoIps.push_back(connection.remoteAddress);
                const bool preferTcp = connection.routedThroughKind == gpd::core::InterfaceKind::VpnTunnel;
                targets.push_back({connection.remoteAddress, connection.localAddress, connection.remotePort, connection.isPrivateDestination, preferTcp});
            }

            const auto clashMatch = clashMatcher_->findFor(connection);
            if (clashMatch.has_value()) {
                connection.clashTracked = true;
                connection.clashOutbound = clashMatch->outboundName;
                connection.clashRule = clashMatch->rule;
                connection.clashChains = clashMatch->chains;
                if (connection.clashOutbound.compare(QStringLiteral("DIRECT"), Qt::CaseInsensitive) == 0) {
                    connection.proxyStatus = QStringLiteral("Без прокси");
                    connection.perRowVerdict = QStringLiteral("Напрямую (clash: DIRECT)");
                } else if (connection.clashOutbound.compare(QStringLiteral("REJECT"), Qt::CaseInsensitive) == 0) {
                    connection.proxyStatus = QStringLiteral("Заблокировано");
                    connection.perRowVerdict = QStringLiteral("Заблокировано через clash");
                } else if (!connection.clashOutbound.isEmpty()) {
                    connection.proxyStatus = QStringLiteral("Через прокси");
                    connection.perRowVerdict = QStringLiteral("Через %1 (clash)").arg(connection.clashOutbound);
                }
            }
        }
        QMetaObject::invokeMethod(this, [this, targets]() { pingScheduler_->updateTargets(targets); }, Qt::QueuedConnection);
        const auto geoMap = geoIp_->lookupBatch(geoIps);
        for (auto& connection : result.connections) {
            if (connection.hasPublicRemoteEndpoint) {
                connection.geoInfo = geoMap.value(connection.remoteAddress);
                const QString pingKey = QStringLiteral("%1|%2").arg(connection.remoteAddress, connection.localAddress);
                connection.pingAggregate = pingSnapshot.value(pingKey);
            }

            if (connection.clashTracked) {
                continue;
            }

            if (!connection.hasPublicRemoteEndpoint || connection.isPrivateDestination) {
                continue;
            }
            if (connection.routedThroughKind == gpd::core::InterfaceKind::Ethernet || connection.routedThroughKind == gpd::core::InterfaceKind::WiFi ||
                connection.routedThroughKind == gpd::core::InterfaceKind::Cellular) {
                connection.tunnelProcessCorrelated = false;
                connection.correlatedTunnelProcessName.clear();
                connection.proxyStatus = QStringLiteral("Без прокси");
                connection.perRowVerdict = QStringLiteral("Напрямую через %1").arg(connection.routedThroughInterfaceName);
            } else if (connection.routedThroughKind == gpd::core::InterfaceKind::VpnTunnel ||
                       connection.routedThroughKind == gpd::core::InterfaceKind::VirtualOverlay) {
                const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
                const QString tunnelProcess = tunnelCorrelator_->hasActiveTunnel(nowMs, 5000, 128);
                const bool tunnelSawSameRemote = tunnelCorrelator_->hasRecentTunnelRemote(connection.remoteAddress, nowMs, 5000);
                const bool tunnelSawOtherRemote = tunnelCorrelator_->hasRecentDifferentTunnelRemote(connection.remoteAddress, nowMs, 5000);
                if (!tunnelProcess.isEmpty()) {
                    connection.tunnelProcessCorrelated = true;
                    connection.correlatedTunnelProcessName = tunnelProcess;
                    if (tunnelSawSameRemote) {
                        connection.proxyStatus = QStringLiteral("Напрямую внутри TUN (вероятно)");
                        connection.perRowVerdict = QStringLiteral("Напрямую внутри TUN (вероятно) через %1").arg(connection.routedThroughInterfaceName);
                    } else if (tunnelSawOtherRemote) {
                        connection.proxyStatus = QStringLiteral("Через прокси (вероятно)");
                        connection.perRowVerdict = QStringLiteral("Через прокси (вероятно) via %1.exe").arg(tunnelProcess);
                    } else {
                        connection.proxyStatus = QStringLiteral("Через прокси");
                        connection.perRowVerdict = QStringLiteral("Через %1.exe").arg(tunnelProcess);
                    }
                } else {
                    connection.tunnelProcessCorrelated = false;
                    connection.correlatedTunnelProcessName.clear();
                    connection.proxyStatus = QStringLiteral("Неизвестно (TUN интерфейс)");
                    connection.perRowVerdict = QStringLiteral("Туннелируется (предположительно) через %1").arg(connection.routedThroughInterfaceName);
                }
            }
        }
        result.verdict = gpd::core::RouteClassifier::classify(result.connections, *tunnelCorrelator_, QDateTime::currentMSecsSinceEpoch());
        return result;
    }));
}

void MainWindow::applyRefreshResult(const RefreshResult& result) {
    lastConnections_ = result.connections;
    qInfo() << "RouteLens refresh pid" << result.selectedPid << "raw" << result.rawConnectionCount << "enriched" << result.connections.size()
            << "etw" << result.etwRunning;
    connectionTable_->setSortingEnabled(false);

    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    for (const auto& connection : result.connections) {
        if (connection.protocol != gpd::core::TransportProtocol::Udp || !connection.observedFromEtw || !connection.hasPublicRemoteEndpoint) {
            continue;
        }
        const QString key = QStringLiteral("%1|%2|%3").arg(connection.pid).arg(connection.remoteAddress).arg(connection.remotePort);
        auto& state = udpQualityByEndpoint_[key];
        if (state.lastUpdateMs > 0) {
            const qint64 dt = nowMs - state.lastUpdateMs;
            const qint64 packetsDelta = static_cast<qint64>(connection.recvPackets) - static_cast<qint64>(state.lastRecvPackets);
            if (dt > 0 && packetsDelta > 0) {
                const double avgInterval = static_cast<double>(dt) / static_cast<double>(packetsDelta);
                const double initialExpected = qBound(kMinExpectedUdpIntervalMs, avgInterval, kMaxExpectedUdpIntervalMs);
                const double expectedInterval = state.expectedIntervalMs > 0.0 ? state.expectedIntervalMs : initialExpected;
                state.expectedIntervalMs += (initialExpected - expectedInterval) / 8.0;
                state.expectedIntervalMs = qBound(kMinExpectedUdpIntervalMs, state.expectedIntervalMs, kMaxExpectedUdpIntervalMs);

                const double instantaneousJitterMs = qAbs(avgInterval - state.expectedIntervalMs) * kUdpJitterAmplification;
                state.jitterMs += (instantaneousJitterMs - state.jitterMs) / 10.0;

                const double queueDriftMs = qMax(0.0, avgInterval - state.expectedIntervalMs);
                const double syntheticRtt = (state.expectedIntervalMs * kUdpBaseRttFactor) + (queueDriftMs * kUdpQueueDelayFactor);
                state.syntheticRttMs = qMax(1, static_cast<int>(qRound(syntheticRtt)));

                const double expectedPackets = static_cast<double>(dt) / state.expectedIntervalMs;
                const double ratio = expectedPackets > 0.0 ? (static_cast<double>(packetsDelta) / expectedPackets) : 1.0;
                const double loss = qBound(0.0, (1.0 - ratio) * 100.0, 100.0);
                state.lossPercent = (state.lossPercent * 0.7) + (loss * 0.3);
            }
        }
        state.lastRecvPackets = connection.recvPackets;
        state.lastSeenMs = connection.lastSeenMs;
        state.lastUpdateMs = nowMs;
    }

    connectionTable_->setRowCount(result.connections.size());
    for (int row = 0; row < result.connections.size(); ++row) {
        fillConnectionRow(row, result.connections[row]);
    }
    connectionTable_->setSortingEnabled(true);
    connectionTable_->sortItems(sortColumn_, sortOrder_);

    verdictBadge_->setVerdict(result.verdict);
    interfacesPanel_->setInterfaces(result.interfaces);

    if (!result.connections.isEmpty()) {
        const gpd::core::ConnectionInfo* selected = nullptr;
        const auto isUsableRemote = [](const gpd::core::ConnectionInfo& c) {
            if (!c.hasRemoteEndpoint || c.remotePort == 0 || c.remoteAddress.startsWith(QLatin1Char('('))) {
                return false;
            }
            if (c.remoteAddress == QStringLiteral("127.0.0.1") || c.remoteAddress == QStringLiteral("::1") ||
                c.remoteAddress == QStringLiteral("0.0.0.0") || c.remoteAddress == QStringLiteral("::")) {
                return false;
            }
            return true;
        };

        for (const auto& c : result.connections) {
            if (isUsableRemote(c) && c.hasPublicRemoteEndpoint) {
                selected = &c;
                break;
            }
        }
        for (const auto& c : result.connections) {
            if (selected == nullptr && isUsableRemote(c)) {
                selected = &c;
                break;
            }
        }
        if (selected == nullptr) {
            selected = &result.connections.first();
        }
        diagnosticEngine_->setTarget(selected->remoteAddress, selected->remotePort, processCombo_->currentText(), selected->localAddress);
        diagnosticEngine_->setConnectionContext(*selected);
        diagnosticEngine_->setTargetPid(selected->pid);
    }
}

void MainWindow::updateCachedInterfaces(const bool forceUpdate) {
    const auto nowMs = QDateTime::currentMSecsSinceEpoch();
    if (!forceUpdate && !cachedInterfaces_.isEmpty() && (nowMs - lastInterfaceRefreshMs_) < 5000) {
        return;
    }

    cachedInterfaces_ = interfaceInspector_->listInterfaces();
    cachedInterfacesByIndex_.clear();
    interfaceIndexByLocalIp_.clear();
    for (const auto& interfaceInfo : cachedInterfaces_) {
        cachedInterfacesByIndex_.insert(interfaceInfo.ifIndex, interfaceInfo);
        for (const auto& ip : interfaceInfo.unicastAddresses) {
            interfaceIndexByLocalIp_.insert(ip, interfaceInfo.ifIndex);
        }
    }
    lastInterfaceRefreshMs_ = nowMs;
    interfacesPanel_->setInterfaces(cachedInterfaces_);
}

void MainWindow::updateMonitoringState() {
    monitoring_ = !monitoring_;
    if (monitoring_) {
        startStopButton_->setText(tr("Остановить"));
        refreshTimer_->start();
        verdictBadge_->setVerdict({gpd::core::RouteVerdict::Unknown, 5, tr("Сканирование соединений активно. Вердикт маршрута появится позже.")});
        pingProbe_->start();
        tcpPingProbe_->start();
        pingScheduler_->start();
        diagnosticEngine_->startContinuous(5000);
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
    diagnosticEngine_->stop();
    pingProbe_->stop();
    tcpPingProbe_->stop();
    startStopButton_->setText(tr("Запустить мониторинг"));
    verdictBadge_->setVerdict({gpd::core::RouteVerdict::Unknown, 0, tr("Мониторинг остановлен.")});
}

void MainWindow::routeToTunnelCorrelator(const QVector<gpd::core::UdpFlowEvent>& events) {
    for (const auto& event : events) {
        std::uint32_t ifIndex = 0;
        auto infoIt = cachedInterfacesByIndex_.cend();

        const auto interfaceIt = interfaceIndexByLocalIp_.constFind(event.localAddress);
        if (interfaceIt != interfaceIndexByLocalIp_.cend()) {
            ifIndex = interfaceIt.value();
            infoIt = cachedInterfacesByIndex_.constFind(ifIndex);
        }

        if (infoIt == cachedInterfacesByIndex_.cend() && !event.remoteAddress.isEmpty()) {
            const auto routeDecision = routeResolver_->resolveRouteFor(event.remoteAddress);
            if (routeDecision.has_value()) {
                ifIndex = routeDecision->ifIndex;
                infoIt = cachedInterfacesByIndex_.constFind(ifIndex);
            }
        }

        if (infoIt == cachedInterfacesByIndex_.cend()) {
            continue;
        }
        tunnelCorrelator_->recordFlow(event.pid,
                                      ifIndex,
                                      infoIt->kind,
                                      event.sizeBytes,
                                      event.isSend,
                                      event.timestampMs,
                                      event.remoteAddress);
    }
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
        countryText = QStringLiteral("Частная сеть");
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
    } else if (connection.protocol == gpd::core::TransportProtocol::Udp && connection.observedFromEtw) {
        const QString key = QStringLiteral("%1|%2|%3").arg(connection.pid).arg(connection.remoteAddress).arg(connection.remotePort);
        const auto state = udpQualityByEndpoint_.value(key);
        int calibratedUdpRttMs = state.syntheticRttMs;
        if (calibratedUdpRttMs > 0 && connection.routedThroughKind == gpd::core::InterfaceKind::VpnTunnel) {
            calibratedUdpRttMs = qMax(1, static_cast<int>(qRound(static_cast<double>(calibratedUdpRttMs) * kVpnTunnelRttFactor)));
        }
        const int transportRttMs = (connection.pingAggregate.samplesInWindow >= 1 && connection.pingAggregate.rttAvgMs >= 0) ? connection.pingAggregate.rttAvgMs : -1;
        const int effectiveRttMs = qMax(transportRttMs, calibratedUdpRttMs);
        if (effectiveRttMs > 0) {
            rttText = QStringLiteral("%1 ms").arg(effectiveRttMs);
        } else {
            rttText = QStringLiteral("н/д");
        }

        if (state.syntheticRttMs > 0) {
            jitterText = QStringLiteral("%1 ms").arg(QString::number(state.jitterMs, 'f', 1));
            lossText = QStringLiteral("%1%").arg(QString::number(state.lossPercent, 'f', 1));
        } else {
            jitterText = QStringLiteral("н/д");
            lossText = QStringLiteral("н/д");
        }
    } else if (connection.pingAggregate.unreachable) {
        rttText = QStringLiteral("недоступен");
        jitterText = QStringLiteral("—");
        lossText = QStringLiteral("100%");
    } else if (connection.pingAggregate.samplesInWindow >= 1 && connection.pingAggregate.rttAvgMs >= 0) {
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
            rttItem->setToolTip(QStringLiteral("ICMP заблокирован, используется TCP fallback"));
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
    dialog.setWindowTitle(tr("Настройка баз GeoIP"));
    auto* layout = makeQtOwned<QVBoxLayout>(&dialog);
    const QString geoDir = gpd::core::GeoIpResolver::defaultGeoDirectory();
    auto* label = makeQtOwned<QLabel>(
        tr("Поместите GeoLite2-Country.mmdb и GeoLite2-ASN.mmdb в:\n%1\n\nБесплатные базы: https://www.maxmind.com/en/geolite2/signup")
            .arg(geoDir),
        &dialog);
    label->setWordWrap(true);
    layout->addWidget(label);
    auto* openButton = makeQtOwned<QPushButton>(tr("Открыть папку данных"), &dialog);
    auto* reloadButton = makeQtOwned<QPushButton>(tr("Перезагрузить базы"), &dialog);
    auto* closeButton = makeQtOwned<QPushButton>(tr("Закрыть"), &dialog);
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

void MainWindow::showInterfaceDetails(const gpd::core::NetworkInterfaceInfo& info) {
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Сведения об интерфейсе: %1").arg(info.friendlyName));
    dialog.resize(820, 560);

    auto* layout = makeQtOwned<QVBoxLayout>(&dialog);

    QStringList lines;
    const QString ownerProcess = detectLikelyOwnerProcess(info);
    lines.push_back(QStringLiteral("Имя: %1").arg(info.friendlyName));
    lines.push_back(QStringLiteral("Описание: %1").arg(info.description));
    lines.push_back(QStringLiteral("Имя адаптера: %1").arg(info.adapterName.isEmpty() ? QStringLiteral("-") : info.adapterName));
    lines.push_back(QStringLiteral("IfIndex: %1").arg(info.ifIndex));
    lines.push_back(QStringLiteral("LUID: %1").arg(info.luid));
    lines.push_back(QStringLiteral("Тип: %1").arg(gpd::core::interfaceKindToString(info.kind)));
    lines.push_back(QStringLiteral("Состояние: %1").arg(info.operStatus == 1U ? QStringLiteral("Вкл") : QStringLiteral("Выкл")));
    lines.push_back(QStringLiteral("IfType: %1, TunnelType: %2").arg(info.ifType).arg(info.tunnelType));
    lines.push_back(QStringLiteral("DNS-суффикс: %1").arg(info.dnsSuffix.isEmpty() ? QStringLiteral("-") : info.dnsSuffix));
    lines.push_back(QStringLiteral("MAC: %1").arg(info.macAddress.isEmpty() ? QStringLiteral("-") : info.macAddress));
    lines.push_back(QStringLiteral("IP-адреса: %1").arg(info.unicastAddresses.isEmpty() ? QStringLiteral("-") : info.unicastAddresses.join(QStringLiteral(", "))));
    lines.push_back(QStringLiteral("Шлюзы: %1").arg(info.gatewayAddresses.isEmpty() ? QStringLiteral("-") : info.gatewayAddresses.join(QStringLiteral(", "))));
    lines.push_back(QStringLiteral("Процесс-владелец: %1").arg(ownerProcess.isEmpty() ? QStringLiteral("неизвестно") : ownerProcess));

    if (!ownerProcess.isEmpty()) {
        qInfo() << "Interface" << info.friendlyName << "likely created by" << ownerProcess;
    } else {
        qInfo() << "Interface" << info.friendlyName << "owner process not detected";
    }

    auto* summary = makeQtOwned<QPlainTextEdit>(lines.join(QStringLiteral("\n")), &dialog);
    summary->setReadOnly(true);
    summary->setMinimumHeight(200);
    layout->addWidget(summary);

    auto* routesLabel = makeQtOwned<QLabel>(tr("Маршруты через этот интерфейс (route print):"), &dialog);
    layout->addWidget(routesLabel);

    QString routesText = tr("Не удалось загрузить маршруты.");
    QProcess process;
    process.start(QStringLiteral("route"), {QStringLiteral("print"), QStringLiteral("-4")});
    if (process.waitForFinished(3000)) {
        const QString output = QString::fromLocal8Bit(process.readAllStandardOutput());
        const QString ifIndexToken = QStringLiteral(" %1 ").arg(info.ifIndex);
        QStringList matched;
        const auto rows = output.split(QChar('\n'));
        for (const auto& rowRaw : rows) {
            const QString row = rowRaw.trimmed();
            if (row.isEmpty()) {
                continue;
            }
            if (row.contains(ifIndexToken) || row.endsWith(QStringLiteral(" %1").arg(info.ifIndex))) {
                matched.push_back(row);
            }
        }
        if (matched.isEmpty()) {
            routesText = tr("В выводе route print не найдено IPv4-маршрутов для этого IfIndex.");
        } else {
            routesText = matched.join(QStringLiteral("\n"));
        }
    }

    auto* routes = makeQtOwned<QPlainTextEdit>(routesText, &dialog);
    routes->setReadOnly(true);
    layout->addWidget(routes, 1);

    auto* closeButton = makeQtOwned<QPushButton>(tr("Закрыть"), &dialog);
    connect(closeButton, &QPushButton::clicked, &dialog, &QDialog::accept);
    layout->addWidget(closeButton);

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

void MainWindow::renderDiagnosticReport(const gpd::core::DiagnosticReport& report) {
    if (diagnosticsView_ == nullptr) {
        return;
    }
    QStringList lines;
    lines.push_back(QStringLiteral("ОТЧЕТ О СОСТОЯНИИ СЕТИ"));
    lines.push_back(QStringLiteral("Цель: %1:%2 (%3)").arg(report.targetIp).arg(report.targetPort).arg(report.targetProcessName));
    lines.push_back(QStringLiteral("Итог: %1").arg(gpd::core::diagnosticStatusToString(report.overallStatus)));
    lines.push_back(QString());
    for (const auto& section : report.sections) {
        lines.push_back(QStringLiteral("[%1] %2").arg(gpd::core::diagnosticStatusToString(section.overallStatus), section.title));
        for (const auto& finding : section.findings) {
            lines.push_back(QStringLiteral("  - %1: %2 (%3)").arg(finding.title, finding.metric, gpd::core::diagnosticStatusToString(finding.status)));
            if (!finding.recommendation.isEmpty()) {
                lines.push_back(QStringLiteral("    -> %1").arg(finding.recommendation));
            }
        }
        lines.push_back(QString());
    }
    diagnosticsView_->setPlainText(lines.join(QStringLiteral("\n")));
}

} // namespace gpd::ui
