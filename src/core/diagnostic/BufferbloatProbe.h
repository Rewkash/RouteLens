#pragma once

#include "core/diagnostic/IDiagnosticProbe.h"

#include <QObject>

class QNetworkAccessManager;
class QNetworkReply;

namespace gpd::core {

class PingScheduler;

class BufferbloatProbe final : public QObject, public IDiagnosticProbe {
    Q_OBJECT
public:
    explicit BufferbloatProbe(PingScheduler* scheduler, QObject* parent = nullptr);

    void setTarget(const QString& ip, const QString& localAddress);
    void runTest(int durationMs = 10000);

    [[nodiscard]] QString probeId() const override;
    bool start() override;
    void stop() override;
    [[nodiscard]] QVariantMap snapshot() const override;

Q_SIGNALS:
    void completed(const QVariantMap& snapshot);

private:
    PingScheduler* scheduler_{nullptr};
    QNetworkAccessManager* network_{nullptr};
    QNetworkReply* reply_{nullptr};
    QString targetIp_;
    QString localAddress_;
    QVariantMap lastSnapshot_;
    qint64 startedAtMs_{0};
    qint64 bytesDownloaded_{0};
    int durationMs_{10000};
    bool running_{false};
};

} // namespace gpd::core
