#include "ui/InterfacesPanel.h"

#include "core/InterfaceClassifier.h"
#include "ui/KindIcon.h"

#include <QHeaderView>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>
#include <QAbstractItemView>

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
    setTitle(tr("Сетевые интерфейсы"));
    setCheckable(true);
    setChecked(false);

    auto* layout = makeQtOwned<QVBoxLayout>(this);
    table_ = makeQtOwned<QTableWidget>(0, 7, this);
    table_->setHorizontalHeaderLabels({
        tr("Имя"),
        tr("Описание"),
        tr("Тип"),
        tr("Статус"),
        tr("IP-адреса"),
        tr("Шлюзы"),
        tr("IfIndex"),
    });
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->verticalHeader()->setVisible(false);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setAlternatingRowColors(true);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    layout->addWidget(table_);

    connect(table_, &QTableWidget::cellDoubleClicked, this, [this](const int row, const int) {
        if (row < 0 || row >= interfaces_.size()) {
            return;
        }
        Q_EMIT interfaceActivated(interfaces_[row]);
    });
}

void InterfacesPanel::setInterfaces(const QVector<gpd::core::NetworkInterfaceInfo>& interfaces) {
    interfaces_ = interfaces;
    table_->setRowCount(interfaces.size());
    for (int row = 0; row < interfaces.size(); ++row) {
        const auto& item = interfaces[row];

        auto* friendly = makeQtOwned<QTableWidgetItem>(item.friendlyName);
        friendly->setIcon(KindIcon::make(item.kind));
        table_->setItem(row, 0, friendly);
        table_->setItem(row, 1, makeQtOwned<QTableWidgetItem>(item.description));
        table_->setItem(row, 2, makeQtOwned<QTableWidgetItem>(gpd::core::interfaceKindToString(item.kind)));
        table_->setItem(row, 3, makeQtOwned<QTableWidgetItem>(item.operStatus == 1U ? QStringLiteral("Вкл") : QStringLiteral("Выкл")));
        table_->setItem(row, 4, makeQtOwned<QTableWidgetItem>(item.unicastAddresses.join(QStringLiteral(", "))));
        table_->setItem(row, 5, makeQtOwned<QTableWidgetItem>(item.gatewayAddresses.join(QStringLiteral(", "))));
        table_->setItem(row, 6, makeQtOwned<QTableWidgetItem>(QString::number(item.ifIndex)));
    }
}

} // namespace gpd::ui
