#pragma once

#include "core/Models.h"

#include <QGroupBox>

class QTableWidget;

namespace gpd::ui {

class InterfacesPanel final : public QGroupBox {
    Q_OBJECT

public:
    explicit InterfacesPanel(QWidget* parent = nullptr);

    void setInterfaces(const QVector<gpd::core::NetworkInterfaceInfo>& interfaces);

Q_SIGNALS:
    void interfaceActivated(gpd::core::NetworkInterfaceInfo info);

private:
    QVector<gpd::core::NetworkInterfaceInfo> interfaces_;
    QTableWidget* table_{nullptr};
};

} // namespace gpd::ui
