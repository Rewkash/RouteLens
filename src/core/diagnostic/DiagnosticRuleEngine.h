#pragma once

#include "core/Models.h"
#include "core/diagnostic/DiagnosticTypes.h"

#include <QHash>
#include <QVariantMap>

namespace gpd::core {

class DiagnosticRuleEngine {
public:
    [[nodiscard]] DiagnosticReport buildReport(const QString& targetIp,
                                               int targetPort,
                                               const QString& processName,
                                               const QHash<QString, QVariantMap>& probeSnapshots,
                                               const ConnectionInfo* connectionInfo = nullptr) const;

    [[nodiscard]] static DiagnosticStatus combineStatuses(const QVector<DiagnosticStatus>& statuses);

private:
    [[nodiscard]] DiagnosticSection evaluateLocal(const QHash<QString, QVariantMap>& snapshots) const;
    [[nodiscard]] DiagnosticSection evaluateFirstHop(const QHash<QString, QVariantMap>& snapshots) const;
    [[nodiscard]] DiagnosticSection evaluateIsp(const QHash<QString, QVariantMap>& snapshots) const;
    [[nodiscard]] DiagnosticSection evaluateVpn(const QHash<QString, QVariantMap>& snapshots, const ConnectionInfo* ci) const;
    [[nodiscard]] DiagnosticSection evaluateGameServer(const QHash<QString, QVariantMap>& snapshots) const;
    [[nodiscard]] DiagnosticSection evaluateBufferbloat(const QHash<QString, QVariantMap>& snapshots) const;
    [[nodiscard]] DiagnosticSection evaluateBackground(const QHash<QString, QVariantMap>& snapshots) const;
};

} // namespace gpd::core
