#pragma once

#include <QObject>
#include <QString>

#include <cstdint>
#include <memory>

namespace gpd::platform {

struct PingResult {
    bool timedOut{true};
    int rttMs{-1};
    QString respondingAddress;
    QString errorMessage;
    std::int64_t completedAtMs{0};
};

class PingProbeWin final : public QObject {
    Q_OBJECT
public:
    explicit PingProbeWin(QObject* parent = nullptr);
    ~PingProbeWin() override;

    [[nodiscard]] bool start();
    void stop();
    void enqueue(const QString& targetKey, const QString& targetIp, int pingTimeoutMs = 1000);

Q_SIGNALS:
    void pingCompleted(QString targetIp, gpd::platform::PingResult result);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace gpd::platform

Q_DECLARE_METATYPE(gpd::platform::PingResult)
