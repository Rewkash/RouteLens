#include "ui/KindIcon.h"

#include <QColor>
#include <QPainter>
#include <QPixmap>

namespace {

QColor kindColor(const gpd::core::InterfaceKind kind) {
    switch (kind) {
    case gpd::core::InterfaceKind::Ethernet:
        return QColor(56, 132, 255);
    case gpd::core::InterfaceKind::VpnTunnel:
        return QColor(255, 146, 43);
    case gpd::core::InterfaceKind::VirtualOverlay:
        return QColor(138, 92, 246);
    case gpd::core::InterfaceKind::WiFi:
        return QColor(70, 186, 255);
    case gpd::core::InterfaceKind::Cellular:
        return QColor(76, 201, 91);
    case gpd::core::InterfaceKind::Loopback:
    case gpd::core::InterfaceKind::VirtualOther:
    case gpd::core::InterfaceKind::Unknown:
        return QColor(130, 130, 130);
    }
    return QColor(130, 130, 130);
}

} // namespace

namespace gpd::ui {

QIcon KindIcon::make(const gpd::core::InterfaceKind kind) {
    QPixmap pixmap(12, 12);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.setBrush(kindColor(kind));
    painter.setPen(Qt::NoPen);
    painter.drawEllipse(1, 1, 10, 10);
    painter.end();

    return QIcon(pixmap);
}

} // namespace gpd::ui
