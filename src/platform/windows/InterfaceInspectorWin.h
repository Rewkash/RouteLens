#pragma once

#include "core/Models.h"

#include <QVector>

namespace gpd::platform {

class InterfaceInspectorWin final {
public:
    [[nodiscard]] QVector<gpd::core::NetworkInterfaceInfo> listInterfaces() const;
};

} // namespace gpd::platform
