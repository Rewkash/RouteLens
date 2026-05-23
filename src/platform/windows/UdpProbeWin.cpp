#include "platform/windows/UdpProbeWin.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <QDateTime>
#include <QMutex>
#include <QMutexLocker>
#include <QQueue>
#include <QRandomGenerator>
#include <QThread>

#include <atomic>

namespace gpd::platform {

namespace {

struct SocketGuard {
    SOCKET socket{INVALID_SOCKET};
    ~SocketGuard() {
        if (socket != INVALID_SOCKET) {
            closesocket(socket);
        }
    }
};

struct Task {
    QString key;
    QString ip;
    std::uint16_t port{0};
    int timeoutMs{1500};
};

bool isSourcePort(const std::uint16_t port) {
    return (port >= 27000 && port <= 27052) || (port >= 27015 && port <= 27040);
}

QByteArray buildPayload(const std::uint16_t port, QString& proto) {
    if (isSourcePort(port)) {
        proto = QStringLiteral("source_a2s");
        return QByteArray("\xFF\xFF\xFF\xFFTSource Engine Query\0", 25);
    }
    proto = QStringLiteral("generic_udp");
    QByteArray payload;
    payload.resize(16);
    for (int i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<char>(QRandomGenerator::global()->generate() & 0xFF);
    }
    return payload;
}

class Worker final : public QThread {
public:
    explicit Worker(UdpProbeWin* owner)
        : owner_(owner) {
    }

    void enqueue(const Task& task) {
        QMutexLocker lock(&mutex_);
        queue_.enqueue(task);
    }

    void requestStop() {
        stop_.store(true);
    }

protected:
    void run() override {
        while (!stop_.load()) {
            Task task;
            {
                QMutexLocker lock(&mutex_);
                if (queue_.isEmpty()) {
                    lock.unlock();
                    msleep(20);
                    continue;
                }
                task = queue_.dequeue();
            }

            UdpProbeResult result;
            const qint64 startedAt = QDateTime::currentMSecsSinceEpoch();
            result.completedAtMs = startedAt;

            addrinfo hints{};
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
            addrinfo* addr = nullptr;
            const QByteArray ipUtf8 = task.ip.toUtf8();
            const QByteArray portUtf8 = QByteArray::number(task.port == 0 ? 27015 : task.port);
            if (getaddrinfo(ipUtf8.constData(), portUtf8.constData(), &hints, &addr) != 0 || addr == nullptr) {
                result.errorMessage = QStringLiteral("Invalid UDP target");
                Q_EMIT owner_->pingCompleted(task.key, result);
                continue;
            }

            SocketGuard sock;
            sock.socket = ::socket(addr->ai_family, SOCK_DGRAM, IPPROTO_UDP);
            if (sock.socket == INVALID_SOCKET) {
                freeaddrinfo(addr);
                result.errorMessage = QStringLiteral("socket() failed");
                Q_EMIT owner_->pingCompleted(task.key, result);
                continue;
            }

            const int timeout = qBound(300, task.timeoutMs, 3000);
            setsockopt(sock.socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

            QString proto;
            const QByteArray payload = buildPayload(task.port, proto);
            result.probeProtocol = proto;
            const int sent = sendto(sock.socket, payload.constData(), payload.size(), 0, addr->ai_addr, static_cast<int>(addr->ai_addrlen));
            if (sent <= 0) {
                const int err = WSAGetLastError();
                result.errorMessage = QStringLiteral("sendto failed %1").arg(err);
                freeaddrinfo(addr);
                Q_EMIT owner_->pingCompleted(task.key, result);
                continue;
            }

            char recvBuffer[2048]{};
            SOCKADDR_STORAGE fromAddr{};
            int fromLen = sizeof(fromAddr);
            const int recvRc = recvfrom(sock.socket, recvBuffer, sizeof(recvBuffer), 0, reinterpret_cast<sockaddr*>(&fromAddr), &fromLen);
            result.completedAtMs = QDateTime::currentMSecsSinceEpoch();
            if (recvRc >= 0) {
                result.timedOut = false;
                result.rttMs = static_cast<int>(result.completedAtMs - startedAt);
            } else {
                const int err = WSAGetLastError();
                if (err == WSAETIMEDOUT) {
                    result.timedOut = true;
                } else if (err == WSAECONNRESET) {
                    result.timedOut = false;
                    result.rttMs = static_cast<int>(result.completedAtMs - startedAt);
                } else {
                    result.timedOut = true;
                    result.errorMessage = QStringLiteral("recvfrom failed %1").arg(err);
                }
            }

            freeaddrinfo(addr);
            Q_EMIT owner_->pingCompleted(task.key, result);
        }
    }

private:
    UdpProbeWin* owner_{nullptr};
    QMutex mutex_;
    QQueue<Task> queue_;
    std::atomic<bool> stop_{false};
};

} // namespace

struct UdpProbeWin::Impl {
    std::unique_ptr<Worker> worker;
};

UdpProbeWin::UdpProbeWin(QObject* parent)
    : QObject(parent)
    , impl_(std::make_unique<Impl>()) {
}

UdpProbeWin::~UdpProbeWin() {
    stop();
}

bool UdpProbeWin::start() {
    if (impl_->worker && impl_->worker->isRunning()) {
        return true;
    }
    impl_->worker = std::make_unique<Worker>(this);
    impl_->worker->start();
    return true;
}

void UdpProbeWin::stop() {
    if (!impl_->worker) {
        return;
    }
    impl_->worker->requestStop();
    impl_->worker->wait(1500);
    impl_->worker.reset();
}

void UdpProbeWin::enqueue(const QString& targetKey, const QString& targetIp, const std::uint16_t targetPort, const int timeoutMs) {
    if (!impl_->worker || !impl_->worker->isRunning()) {
        return;
    }
    impl_->worker->enqueue(Task{targetKey, targetIp, targetPort, timeoutMs});
}

} // namespace gpd::platform
