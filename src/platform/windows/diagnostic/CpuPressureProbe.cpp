#include "platform/windows/diagnostic/CpuPressureProbe.h"

#include <windows.h>

namespace gpd::platform {

namespace {

ULONGLONG fileTimeToU64(const FILETIME& ft) {
    ULARGE_INTEGER u{};
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

} // namespace

QString CpuPressureProbe::probeId() const {
    return QStringLiteral("cpu_pressure");
}

bool CpuPressureProbe::start() {
    initialized_ = false;
    return true;
}

void CpuPressureProbe::stop() {
}

QVariantMap CpuPressureProbe::snapshot() const {
    QVariantMap out;
    FILETIME idle{}, kernel{}, user{};
    if (!GetSystemTimes(&idle, &kernel, &user)) {
        return out;
    }
    double cpuPercent = 0.0;
    if (initialized_) {
        const double idleDelta = fileTimeDeltaMs(lastIdle_, idle);
        const double kernelDelta = fileTimeDeltaMs(lastKernel_, kernel);
        const double userDelta = fileTimeDeltaMs(lastUser_, user);
        const double total = kernelDelta + userDelta;
        if (total > 0.0) {
            cpuPercent = qBound(0.0, ((total - idleDelta) / total) * 100.0, 100.0);
        }
    }
    lastIdle_ = idle;
    lastKernel_ = kernel;
    lastUser_ = user;
    initialized_ = true;

    out.insert(QStringLiteral("processCpuPercent"), 0.0);
    out.insert(QStringLiteral("systemCpuPercent"), cpuPercent);
    return out;
}

double CpuPressureProbe::fileTimeDeltaMs(const FILETIME& a, const FILETIME& b) {
    const auto ta = fileTimeToU64(a);
    const auto tb = fileTimeToU64(b);
    if (tb < ta) {
        return 0.0;
    }
    return static_cast<double>(tb - ta) / 10000.0;
}

} // namespace gpd::platform
