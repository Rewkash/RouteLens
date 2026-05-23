#pragma once

#include <QString>
#include <QVariantMap>

namespace gpd::core {

class IDiagnosticProbe {
public:
    virtual ~IDiagnosticProbe() = default;
    [[nodiscard]] virtual QString probeId() const = 0;
    virtual bool start() = 0;
    virtual void stop() = 0;
    [[nodiscard]] virtual QVariantMap snapshot() const = 0;
};

} // namespace gpd::core
