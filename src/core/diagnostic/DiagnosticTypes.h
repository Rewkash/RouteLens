#pragma once

#include <QString>
#include <QVector>
#include <QMetaType>

#include <cstdint>

namespace gpd::core {

enum class DiagnosticStatus {
    Ok,
    Info,
    Warning,
    Problem,
    Severe,
    Unknown,
};

struct DiagnosticFinding {
    QString sectionId;
    QString title;
    QString metric;
    DiagnosticStatus status{DiagnosticStatus::Unknown};
    QString recommendation;
    std::int64_t timestampMs{0};
};

struct DiagnosticSection {
    QString id;
    QString title;
    DiagnosticStatus overallStatus{DiagnosticStatus::Unknown};
    QVector<DiagnosticFinding> findings;
};

struct DiagnosticReport {
    std::int64_t startedAtMs{0};
    std::int64_t completedAtMs{0};
    QString targetIp;
    int targetPort{0};
    QString targetProcessName;
    QString targetCountry;
    QVector<DiagnosticSection> sections;
    DiagnosticStatus overallStatus{DiagnosticStatus::Unknown};
};

QString diagnosticStatusToString(DiagnosticStatus status);

} // namespace gpd::core

Q_DECLARE_METATYPE(gpd::core::DiagnosticFinding)
Q_DECLARE_METATYPE(gpd::core::DiagnosticSection)
Q_DECLARE_METATYPE(gpd::core::DiagnosticReport)
