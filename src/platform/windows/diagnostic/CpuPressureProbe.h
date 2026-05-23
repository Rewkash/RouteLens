#pragma once

#include "core/diagnostic/IDiagnosticProbe.h"

#include <windows.h>

namespace gpd::platform {

class CpuPressureProbe final : public gpd::core::IDiagnosticProbe {
public:
    [[nodiscard]] QString probeId() const override;
    bool start() override;
    void stop() override;
    [[nodiscard]] QVariantMap snapshot() const override;

private:
    static double fileTimeDeltaMs(const FILETIME& a, const FILETIME& b);
    mutable bool initialized_{false};
    mutable FILETIME lastIdle_{};
    mutable FILETIME lastKernel_{};
    mutable FILETIME lastUser_{};
};

} // namespace gpd::platform
