#include "platform/windows/diagnostic/AdapterErrorProbe.h"

#include <QDateTime>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

namespace gpd::platform {

QString AdapterErrorProbe::probeId() const {
    return QStringLiteral("adapter_errors");
}

bool AdapterErrorProbe::start() {
    initialized_ = false;
    return true;
}

void AdapterErrorProbe::stop() {
}

QVariantMap AdapterErrorProbe::snapshot() const {
    QVariantMap out;
    PMIB_IF_TABLE2 table = nullptr;
    if (GetIfTable2(&table) != NO_ERROR || table == nullptr) {
        return out;
    }

    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    const MIB_IF_ROW2* best = nullptr;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const auto& row = table->Table[i];
        if (row.OperStatus != IfOperStatusUp) {
            continue;
        }
        if (row.Type == IF_TYPE_SOFTWARE_LOOPBACK) {
            continue;
        }
        if (best == nullptr || row.InOctets + row.OutOctets > best->InOctets + best->OutOctets) {
            best = &row;
        }
    }

    if (best != nullptr) {
        const std::uint64_t inErr = best->InErrors;
        const std::uint64_t outErr = best->OutErrors;
        double inPerSec = 0.0;
        double outPerSec = 0.0;
        if (initialized_ && nowMs > lastSampleMs_) {
            const double dtSec = static_cast<double>(nowMs - lastSampleMs_) / 1000.0;
            if (dtSec > 0.0) {
                inPerSec = static_cast<double>(inErr - lastInErrors_) / dtSec;
                outPerSec = static_cast<double>(outErr - lastOutErrors_) / dtSec;
            }
        }
        lastInErrors_ = inErr;
        lastOutErrors_ = outErr;
        lastSampleMs_ = nowMs;
        initialized_ = true;
        ifName_ = QString::fromWCharArray(best->Description);

        out.insert(QStringLiteral("interfaceName"), ifName_);
        out.insert(QStringLiteral("inErrorsPerSec"), inPerSec);
        out.insert(QStringLiteral("outErrorsPerSec"), outPerSec);
        out.insert(QStringLiteral("inDiscardsPerSec"), 0.0);
        out.insert(QStringLiteral("outDiscardsPerSec"), 0.0);
    }

    FreeMibTable(table);
    return out;
}

} // namespace gpd::platform
