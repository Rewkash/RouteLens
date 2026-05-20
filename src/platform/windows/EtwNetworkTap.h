#pragma once

#include "core/Models.h"

#include <QMetaType>
#include <QObject>

#include <atomic>
#include <cstdint>
#include <mutex>
#include <thread>

namespace gpd::platform {

enum class EtwStatus {
    Stopped,
    Starting,
    Running,
    Failed,
};

struct EtwStartError {
    std::uint32_t lastError{0};
    QString message;
};

class EtwNetworkTap final : public QObject {
    Q_OBJECT

public:
    explicit EtwNetworkTap(QObject* parent = nullptr);
    ~EtwNetworkTap() override;

    [[nodiscard]] bool start();
    void stop();
    [[nodiscard]] EtwStatus status() const noexcept;
    [[nodiscard]] EtwStartError lastError() const noexcept;
    void dispatchUdpBatch(QVector<gpd::core::UdpFlowEvent> events);

Q_SIGNALS:
    void statusChanged(EtwStatus newStatus);
    void udpEventBatch(QVector<gpd::core::UdpFlowEvent> events);

private:
    void runTraceLoop();
    void setStatus(EtwStatus status);

    std::atomic<EtwStatus> status_{EtwStatus::Stopped};
    std::atomic_bool stopRequested_{false};
    std::thread worker_;
    mutable std::mutex stateMutex_;
    EtwStartError lastError_;
};

} // namespace gpd::platform

Q_DECLARE_METATYPE(gpd::platform::EtwStatus)
