#pragma once

#include "platform/windows/PingProbeWin.h"

#include <QObject>
#include <QString>

#include <cstdint>
#include <memory>

namespace gpd::platform {

class TcpPingProbeWin final : public QObject {
    Q_OBJECT
public:
    explicit TcpPingProbeWin(QObject* parent = nullptr);
    ~TcpPingProbeWin() override;

    void start();
    void stop();
    void enqueue(const QString& targetKey, const QString& targetIp, const QString& localBindIp, std::uint16_t port, int timeoutMs = 1500);

Q_SIGNALS:
    void pingCompleted(QString targetIp, gpd::platform::PingResult result);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace gpd::platform
