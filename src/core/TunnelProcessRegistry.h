#pragma once

#include <QString>
#include <QVector>

namespace gpd::core {

class TunnelProcessRegistry final {
public:
    [[nodiscard]] static bool isKnownTunnel(const QString& processName);
    [[nodiscard]] static QString categoryFor(const QString& processName);
    [[nodiscard]] static QVector<QString> knownNames();
};

} // namespace gpd::core
