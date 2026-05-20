#pragma once

#include "core/Models.h"

namespace gpd::core {

class InterfaceClassifier final {
public:
    [[nodiscard]] static InterfaceKind classify(const NetworkInterfaceInfo& interfaceInfo);
};

} // namespace gpd::core
