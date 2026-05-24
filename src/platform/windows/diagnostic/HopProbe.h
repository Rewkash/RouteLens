#pragma once

#include "core/diagnostic/IDiagnosticProbe.h"

#include <QObject>

class QProcess;

namespace gpd::platform {

class HopProbe final : public QObject, public gpd::core::IDiagnosticProbe {
    Q_OBJECT
public:
    explicit HopProbe(QObject* parent = nullptr);

    void setTarget(const QString& ip);
    void runTest();

    [[nodiscard]] QString probeId() const override;
    bool start() override;
    void stop() override;
    [[nodiscard]] QVariantMap snapshot() const override;

Q_SIGNALS:
    void completed(const QVariantMap& snapshot);

private:
    void parseOutput(const QString& output);

    QString targetIp_;
    QVariantMap lastSnapshot_;
    QProcess* process_{nullptr};
};

} // namespace gpd::platform
