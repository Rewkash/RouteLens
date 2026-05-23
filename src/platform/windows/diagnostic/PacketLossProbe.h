#pragma once

#include "core/diagnostic/IDiagnosticProbe.h"

#include <QObject>

class QProcess;

namespace gpd::platform {

class PacketLossProbe final : public QObject, public gpd::core::IDiagnosticProbe {
    Q_OBJECT
public:
    explicit PacketLossProbe(QObject* parent = nullptr);

    void setTarget(const QString& targetIp, const QString& localAddress);
    void runTest();

    [[nodiscard]] QString probeId() const override;
    bool start() override;
    void stop() override;
    [[nodiscard]] QVariantMap snapshot() const override;

Q_SIGNALS:
    void completed(const QVariantMap& snapshot);

private:
    void runNext();
    void parseAndStore(const QString& key, const QString& output);
    QString detectPhysicalDefaultGateway() const;

    QString targetIp_;
    QString localAddress_;
    QString gatewayIp_;
    QVariantMap lastSnapshot_;
    QProcess* process_{nullptr};
    QString currentKey_;
    QStringList queue_;
};

} // namespace gpd::platform
