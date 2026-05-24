#include "core/diagnostic/DiagnosticTypes.h"

namespace gpd::core {

QString diagnosticStatusToString(const DiagnosticStatus status) {
    switch (status) {
    case DiagnosticStatus::Ok:
        return QStringLiteral("Норма");
    case DiagnosticStatus::Info:
        return QStringLiteral("Инфо");
    case DiagnosticStatus::Warning:
        return QStringLiteral("Предупреждение");
    case DiagnosticStatus::Problem:
        return QStringLiteral("Проблема");
    case DiagnosticStatus::Severe:
        return QStringLiteral("Критично");
    case DiagnosticStatus::Unknown:
    default:
        return QStringLiteral("Неизвестно");
    }
}

} // namespace gpd::core
