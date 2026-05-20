#pragma once

#include "core/Models.h"

#include <QMainWindow>
#include <QHash>
#include <QFutureWatcher>
#include <Qt>

#include <cstdint>
#include <memory>

class QComboBox;
class QPushButton;
class QTableWidget;
class QTimer;
class QLabel;
class QAction;

namespace gpd::platform {
class ProcessMonitorWin;
class ConnectionScannerWin;
class InterfaceInspectorWin;
class RouteResolverWin;
class EtwNetworkTap;
}

namespace gpd::core {
class UdpFlowAggregator;
class GeoIpResolver;
class PingScheduler;
struct TargetEndpoint;
}

namespace gpd::platform {
class PingProbeWin;
class TcpPingProbeWin;
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
    void restoreTableSortState();
    void persistTableSortState() const;

    QComboBox* processCombo_{nullptr};
    QPushButton* refreshButton_{nullptr};
    QPushButton* startStopButton_{nullptr};
    VerdictBadge* verdictBadge_{nullptr};
    QTableWidget* connectionTable_{nullptr};
    InterfacesPanel* interfacesPanel_{nullptr};
    QLabel* etwStatusLabel_{nullptr};
    QLabel* geoStatusLabel_{nullptr};
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
    std::unique_ptr<gpd::core::UdpFlowAggregator> udpFlows_;
    std::unique_ptr<gpd::core::GeoIpResolver> geoIp_;
    std::unique_ptr<gpd::platform::PingProbeWin> pingProbe_;
    std::unique_ptr<gpd::platform::TcpPingProbeWin> tcpPingProbe_;
    std::unique_ptr<gpd::core::PingScheduler> pingScheduler_;
    QVector<gpd::core::NetworkInterfaceInfo> cachedInterfaces_;
    QHash<std::uint32_t, gpd::core::NetworkInterfaceInfo> cachedInterfacesByIndex_;
    int sortColumn_{0};
    Qt::SortOrder sortOrder_{Qt::AscendingOrder};
};

} // namespace gpd::ui
