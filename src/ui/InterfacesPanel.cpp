#include "ui/InterfacesPanel.h"

#include "core/InterfaceClassifier.h"
#include "ui/KindIcon.h"

#include <QHeaderView>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <QSet>
#include <memory>
#include <utility>

namespace {

template <typename T, typename... Args>
T* makeQtOwned(Args&&... args) {
    return std::make_unique<T>(std::forward<Args>(args)...).release();
}

} // namespace

namespace gpd::ui {

InterfacesPanel::InterfacesPanel(QWidget* parent)
    : QGroupBox(parent) {
    setTitle(tr("Network interfaces"));
    setCheckable(true);
    setChecked(true);
    setMinimumHeight(220);

    auto* layout = makeQtOwned<QVBoxLayout>(this);
    table_ = makeQtOwned<QTableWidget>(0, 7, this);
    table_->setHorizontalHeaderLabels({
        tr("Friendly Name"),
        tr("Description"),
        tr("Kind"),
        tr("Status"),
        tr("IP Addresses"),
        tr("Gateways"),
        tr("IfIndex"),
    });
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->verticalHeader()->setVisible(false);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setAlternatingRowColors(true);
    layout->addWidget(table_);
}

void InterfacesPanel::setInterfaces(const QVector<gpd::core::NetworkInterfaceInfo>& interfaces) {
    table_->setRowCount(interfaces.size());
    for (int row = 0; row < interfaces.size(); ++row) {
        const auto& item = interfaces[row];

        QSet<QString> uniqIp;
        for (const auto& ip : item.unicastAddresses) {
            if (!ip.isEmpty() && ip != QStringLiteral("0.0.0.0") && ip != QStringLiteral("::")) {
                uniqIp.insert(ip);
            }
        }
        QSet<QString> uniqGw;
        for (const auto& gw : item.gatewayAddresses) {
            if (!gw.isEmpty()) {
                uniqGw.insert(gw);
            }
        }

        auto* friendly = makeQtOwned<QTableWidgetItem>(item.friendlyName);
        friendly->setIcon(KindIcon::make(item.kind));
        table_->setItem(row, 0, friendly);
        table_->setItem(row, 1, makeQtOwned<QTableWidgetItem>(item.description));
        table_->setItem(row, 2, makeQtOwned<QTableWidgetItem>(gpd::core::interfaceKindToString(item.kind)));
        table_->setItem(row, 3, makeQtOwned<QTableWidgetItem>(item.operStatus == 1U ? QStringLiteral("Up") : QStringLiteral("Down")));
        table_->setItem(row, 4, makeQtOwned<QTableWidgetItem>(QStringList(uniqIp.cbegin(), uniqIp.cend()).join(QStringLiteral(", "))));
        table_->setItem(row, 5, makeQtOwned<QTableWidgetItem>(QStringList(uniqGw.cbegin(), uniqGw.cend()).join(QStringLiteral(", "))));
        table_->setItem(row, 6, makeQtOwned<QTableWidgetItem>(QString::number(item.ifIndex)));
    }
}

} // namespace gpd::ui
