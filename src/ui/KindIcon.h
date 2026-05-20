#pragma once

#include "core/Models.h"

#include <QIcon>

namespace gpd::ui {

class KindIcon final {
public:
    [[nodiscard]] static QIcon make(gpd::core::InterfaceKind kind);
};

} // namespace gpd::ui
