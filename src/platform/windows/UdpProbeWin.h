#pragma once

#include <QObject>
#include <QString>

#include <cstdint>
#include <memory>

namespace gpd::platform {

struct UdpProbeResult {
    bool timedOut{true};
    int rttMs{-1};
    QString errorMessage;
    std::int64_t completedAtMs{0};
    QString probeProtocol;
};

class UdpProbeWin final : public QObject {
    Q_OBJECT
public:
    explicit UdpProbeWin(QObject* parent = nullptr);
    ~UdpProbeWin() override;

    bool start();
    void stop();
    void enqueue(const QString& targetKey, const QString& targetIp, std::uint16_t targetPort, int timeoutMs = 1500);

Q_SIGNALS:
    void pingCompleted(QString targetKey, gpd::platform::UdpProbeResult result);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace gpd::platform

Q_DECLARE_METATYPE(gpd::platform::UdpProbeResult)
