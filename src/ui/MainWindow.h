#pragma once

#include "core/Models.h"

#include <QMainWindow>
#include <QHash>
#include <QFutureWatcher>
#include <Qt>

#include <cstdint>
#include <memory>

class QDateTime;
class QPlainTextEdit;

class QComboBox;
class QPushButton;
class QTableWidget;
class QTimer;
class QLabel;
class QAction;
class QProgressBar;

namespace gpd::platform {
class ProcessMonitorWin;
class ConnectionScannerWin;
class InterfaceInspectorWin;
class RouteResolverWin;
class EtwNetworkTap;
}

namespace gpd::core {
class ClashApiClient;
class ClashConnectionMatcher;
class DiagnosticEngine;
struct DiagnosticReport;
class UdpFlowAggregator;
class GeoIpResolver;
class PingScheduler;
class TunnelCorrelator;
struct TargetEndpoint;
}

namespace gpd::platform {
class PingProbeWin;
class TcpPingProbeWin;
class UdpProbeWin;
}

namespace gpd::ui {

class VerdictBadge;
class InterfacesPanel;

struct RefreshResult {
    QVector<gpd::core::ConnectionInfo> connections;
    QVector<gpd::core::NetworkInterfaceInfo> interfaces;
    gpd::core::VerdictSummary verdict;
    QHash<std::uint32_t, gpd::core::NetworkInterfaceInfo> interfacesByIndex;
    std::uint32_t selectedPid{0};
    int rawConnectionCount{0};
    bool etwRunning{false};
    bool geoReady{false};
};

class MainWindow final : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

private:
    void buildUi();
    void refreshProcesses();
    void refreshConnections();
    void updateMonitoringState();
    void fillConnectionRow(int row, const gpd::core::ConnectionInfo& connection);
    void applyRefreshResult(const RefreshResult& result);
    void updateCachedInterfaces(bool forceUpdate);
    void configureGeoIp();
    void showInterfaceDetails(const gpd::core::NetworkInterfaceInfo& info);
    void restoreTableSortState();
    void persistTableSortState() const;
    void routeToTunnelCorrelator(const QVector<gpd::core::UdpFlowEvent>& events);
    void renderDiagnosticReport(const gpd::core::DiagnosticReport& report);

    QComboBox* processCombo_{nullptr};
    QPushButton* refreshButton_{nullptr};
    QPushButton* startStopButton_{nullptr};
    VerdictBadge* verdictBadge_{nullptr};
    QTableWidget* connectionTable_{nullptr};
    InterfacesPanel* interfacesPanel_{nullptr};
    QLabel* etwStatusLabel_{nullptr};
    QLabel* geoStatusLabel_{nullptr};
    QLabel* clashStatusLabel_{nullptr};
    QPushButton* runDiagnosticButton_{nullptr};
    QPushButton* exportDiagnosticButton_{nullptr};
    QProgressBar* diagnosticProgress_{nullptr};
    QPlainTextEdit* diagnosticsView_{nullptr};
    QAction* configureGeoIpAction_{nullptr};
    QTimer* refreshTimer_{nullptr};
    QTimer* pruneTimer_{nullptr};
    bool monitoring_{false};
    bool refreshInFlight_{false};
    qint64 lastInterfaceRefreshMs_{0};
    QFutureWatcher<RefreshResult> refreshWatcher_;
    std::unique_ptr<gpd::platform::ProcessMonitorWin> processMonitor_;
    std::unique_ptr<gpd::platform::ConnectionScannerWin> connectionScanner_;
    std::unique_ptr<gpd::platform::InterfaceInspectorWin> interfaceInspector_;
    std::unique_ptr<gpd::platform::RouteResolverWin> routeResolver_;
    std::unique_ptr<gpd::platform::EtwNetworkTap> etwTap_;
    std::unique_ptr<gpd::core::ClashApiClient> clashApi_;
    std::unique_ptr<gpd::core::ClashConnectionMatcher> clashMatcher_;
    std::unique_ptr<gpd::core::UdpFlowAggregator> udpFlows_;
    std::unique_ptr<gpd::core::GeoIpResolver> geoIp_;
    std::unique_ptr<gpd::platform::PingProbeWin> pingProbe_;
    std::unique_ptr<gpd::platform::TcpPingProbeWin> tcpPingProbe_;
    std::unique_ptr<gpd::platform::UdpProbeWin> udpProbe_;
    std::unique_ptr<gpd::core::PingScheduler> pingScheduler_;
    std::unique_ptr<gpd::core::TunnelCorrelator> tunnelCorrelator_;
    std::unique_ptr<gpd::core::DiagnosticEngine> diagnosticEngine_;
    QVector<gpd::core::NetworkInterfaceInfo> cachedInterfaces_;
    QHash<std::uint32_t, gpd::core::NetworkInterfaceInfo> cachedInterfacesByIndex_;
    QHash<QString, std::uint32_t> interfaceIndexByLocalIp_;
    QHash<std::uint32_t, QString> registeredTunnelPids_;
    QVector<gpd::core::ConnectionInfo> lastConnections_;
    int sortColumn_{0};
    Qt::SortOrder sortOrder_{Qt::AscendingOrder};

    struct UdpQualityState {
        std::uint64_t lastRecvPackets{0};
        std::int64_t lastSeenMs{0};
        std::int64_t lastUpdateMs{0};
        double expectedIntervalMs{0.0};
        double jitterMs{0.0};
        double lossPercent{0.0};
        int syntheticRttMs{-1};
    };
    QHash<QString, UdpQualityState> udpQualityByEndpoint_;
};

} // namespace gpd::ui
