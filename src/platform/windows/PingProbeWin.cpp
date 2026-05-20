#include "platform/windows/PingProbeWin.h"

#include <winsock2.h>
#include <ipexport.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <icmpapi.h>

#include <QDateTime>
#include <QMetaObject>
#include <QMutex>
#include <QMutexLocker>
#include <QQueue>
#include <QThread>

#include <atomic>

namespace gpd::platform {

namespace {

struct IcmpHandle {
    HANDLE handle{INVALID_HANDLE_VALUE};
    ~IcmpHandle() {
        if (handle != INVALID_HANDLE_VALUE) {
            IcmpCloseHandle(handle);
        }
    }
};

struct PingTask {
    QString ip;
    int timeoutMs{1000};
};

class Worker final : public QThread {
public:
    explicit Worker(PingProbeWin* owner)
        : owner_(owner) {}

    void enqueue(const PingTask& task) {
        QMutexLocker lock(&mutex_);
        queue_.enqueue(task);
    }

    void requestStop() {
        stopRequested_.store(true);
    }

protected:
    void run() override {
        IcmpHandle icmp4;
        icmp4.handle = IcmpCreateFile();
        while (!stopRequested_.load()) {
            PingTask task;
            {
                QMutexLocker lock(&mutex_);
                if (queue_.isEmpty()) {
                    lock.unlock();
                    msleep(20);
                    continue;
                }
                task = queue_.dequeue();
            }

            PingResult result;
            result.completedAtMs = QDateTime::currentMSecsSinceEpoch();

            in_addr addr4{};
            if (InetPtonW(AF_INET, reinterpret_cast<LPCWSTR>(task.ip.utf16()), &addr4) != 1 || icmp4.handle == INVALID_HANDLE_VALUE) {
                result.errorMessage = QStringLiteral("Unsupported IP or ICMP init failed");
                QMetaObject::invokeMethod(owner_, [owner = owner_, ip = task.ip, result]() { Q_EMIT owner->pingCompleted(ip, result); }, Qt::QueuedConnection);
                continue;
            }

            char payload[32]{};
            alignas(ICMP_ECHO_REPLY) unsigned char buffer[sizeof(ICMP_ECHO_REPLY) + sizeof(payload) + 8]{};
            const DWORD started = GetTickCount();
            const DWORD reply = IcmpSendEcho(icmp4.handle,
                                             addr4.S_un.S_addr,
                                             payload,
                                             static_cast<WORD>(sizeof(payload)),
                                             nullptr,
                                             buffer,
                                             static_cast<DWORD>(sizeof(buffer)),
                                             static_cast<DWORD>(qBound(50, task.timeoutMs, 2000)));
            result.completedAtMs = QDateTime::currentMSecsSinceEpoch();
            if (reply == 0) {
                const DWORD err = GetLastError();
                result.timedOut = true;
                if (err != IP_REQ_TIMED_OUT && err != IP_DEST_NET_UNREACHABLE && err != IP_DEST_HOST_UNREACHABLE) {
                    result.errorMessage = QStringLiteral("ICMP error %1").arg(err);
                }
                QMetaObject::invokeMethod(owner_, [owner = owner_, ip = task.ip, result]() { Q_EMIT owner->pingCompleted(ip, result); }, Qt::QueuedConnection);
                continue;
            }

            auto* echo = reinterpret_cast<ICMP_ECHO_REPLY*>(buffer);
            result.timedOut = false;
            result.rttMs = static_cast<int>(echo->RoundTripTime);
            if (result.rttMs < 0) {
                result.rttMs = static_cast<int>(GetTickCount() - started);
            }
            if (result.rttMs <= 0) {
                result.rttMs = 1;
            }
            result.respondingAddress = task.ip;
            QMetaObject::invokeMethod(owner_, [owner = owner_, ip = task.ip, result]() { Q_EMIT owner->pingCompleted(ip, result); }, Qt::QueuedConnection);
        }
    }

private:
    PingProbeWin* owner_{nullptr};
    QMutex mutex_;
    QQueue<PingTask> queue_;
    std::atomic<bool> stopRequested_{false};
};

} // namespace

struct PingProbeWin::Impl {
    std::unique_ptr<Worker> worker;
};

PingProbeWin::PingProbeWin(QObject* parent)
    : QObject(parent)
    , impl_(std::make_unique<Impl>()) {}

PingProbeWin::~PingProbeWin() {
    stop();
}

bool PingProbeWin::start() {
    if (impl_->worker && impl_->worker->isRunning()) {
        return true;
    }
    impl_->worker = std::make_unique<Worker>(this);
    impl_->worker->start();
    return true;
}

void PingProbeWin::stop() {
    if (!impl_->worker) {
        return;
    }
    impl_->worker->requestStop();
    impl_->worker->wait(1500);
    impl_->worker.reset();
}

void PingProbeWin::enqueue(const QString& targetIp, const int pingTimeoutMs) {
    if (!impl_->worker || !impl_->worker->isRunning()) {
        return;
    }
    impl_->worker->enqueue(PingTask{targetIp, pingTimeoutMs});
}

} // namespace gpd::platform
