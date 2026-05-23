#pragma once

#include "core/diagnostic/IDiagnosticProbe.h"

#include <cstdint>

namespace gpd::platform {

class AdapterErrorProbe final : public gpd::core::IDiagnosticProbe {
public:
    [[nodiscard]] QString probeId() const override;
    bool start() override;
    void stop() override;
    [[nodiscard]] QVariantMap snapshot() const override;

private:
    mutable bool initialized_{false};
    mutable std::uint64_t lastInErrors_{0};
    mutable std::uint64_t lastOutErrors_{0};
    mutable std::int64_t lastSampleMs_{0};
    mutable QString ifName_;
};

} // namespace gpd::platform
