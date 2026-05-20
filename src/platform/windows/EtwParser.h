#pragma once

#include "core/Models.h"

#include <optional>

namespace gpd::platform {

class EtwParser final {
public:
    EtwParser() = default;
    [[nodiscard]] std::optional<gpd::core::UdpFlowEvent> parse(const void* record) const;
};

} // namespace gpd::platform
