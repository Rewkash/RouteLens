#pragma once

#include "core/Models.h"

#include <QMainWindow>
#include <QHash>
#include <QFutureWatcher>

#include <cstdint>
#include <memory>

class QComboBox;
class QPushButton;
class QTableWidget;
class QTimer;

namespace gpd::platform {
class ProcessMonitorWin;
class ConnectionScannerWin;
class InterfaceInspectorWin;
class RouteResolverWin;
}

namespace gpd::ui {

class VerdictBadge;
class InterfacesPanel;

struct RefreshResult {
    QVector<gpd::core::ConnectionInfo> connections;
    QVector<gpd::core::NetworkInterfaceInfo> interfaces;
    gpd::core::VerdictSummary verdict;
    QHash<std::uint32_t, gpd::core::NetworkInterfaceInfo> interfacesByIndex;
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

    QComboBox* processCombo_{nullptr};
    QPushButton* refreshButton_{nullptr};
    QPushButton* startStopButton_{nullptr};
    VerdictBadge* verdictBadge_{nullptr};
    QTableWidget* connectionTable_{nullptr};
    InterfacesPanel* interfacesPanel_{nullptr};
    QTimer* refreshTimer_{nullptr};
    bool monitoring_{false};
    bool refreshInFlight_{false};
    qint64 lastInterfaceRefreshMs_{0};
    QFutureWatcher<RefreshResult> refreshWatcher_;
    std::unique_ptr<gpd::platform::ProcessMonitorWin> processMonitor_;
    std::unique_ptr<gpd::platform::ConnectionScannerWin> connectionScanner_;
    std::unique_ptr<gpd::platform::InterfaceInspectorWin> interfaceInspector_;
    std::unique_ptr<gpd::platform::RouteResolverWin> routeResolver_;
    QVector<gpd::core::NetworkInterfaceInfo> cachedInterfaces_;
    QHash<std::uint32_t, gpd::core::NetworkInterfaceInfo> cachedInterfacesByIndex_;
};

} // namespace gpd::ui
