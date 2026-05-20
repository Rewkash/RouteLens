#pragma once

#include <QMainWindow>

#include <memory>

class QComboBox;
class QPushButton;
class QTableWidget;
class QTimer;

namespace gpd::core {
struct ConnectionInfo;
}

namespace gpd::platform {
class ProcessMonitorWin;
class ConnectionScannerWin;
}

namespace gpd::ui {

class VerdictBadge;

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

    QComboBox* processCombo_{nullptr};
    QPushButton* refreshButton_{nullptr};
    QPushButton* startStopButton_{nullptr};
    VerdictBadge* verdictBadge_{nullptr};
    QTableWidget* connectionTable_{nullptr};
    QTimer* refreshTimer_{nullptr};
    bool monitoring_{false};
    std::unique_ptr<gpd::platform::ProcessMonitorWin> processMonitor_;
    std::unique_ptr<gpd::platform::ConnectionScannerWin> connectionScanner_;
};

} // namespace gpd::ui
