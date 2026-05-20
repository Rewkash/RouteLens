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

private:
    QTableWidget* table_{nullptr};
};

} // namespace gpd::ui
