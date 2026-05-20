#include "platform/windows/TcpPingProbeWin.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <QDateTime>
#include <QMetaObject>
#include <QMutex>
#include <QMutexLocker>
#include <QQueue>
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
    QString ip;
    std::uint16_t port{0};
    int timeoutMs{1500};
};

class Worker final : public QThread {
public:
    explicit Worker(TcpPingProbeWin* owner)
        : owner_(owner) {}

    void enqueue(const Task& t) {
        QMutexLocker lock(&mutex_);
        queue_.enqueue(t);
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

            PingResult result;
            const qint64 started = QDateTime::currentMSecsSinceEpoch();
            result.completedAtMs = started;

            addrinfo hints{};
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
            addrinfo* addr = nullptr;
            const QByteArray ipUtf8 = task.ip.toUtf8();
            const QByteArray portUtf8 = QByteArray::number(task.port);
            if (getaddrinfo(ipUtf8.constData(), portUtf8.constData(), &hints, &addr) != 0 || addr == nullptr) {
                result.errorMessage = QStringLiteral("Invalid TCP target");
                QMetaObject::invokeMethod(owner_, [owner = owner_, ip = task.ip, result]() { Q_EMIT owner->pingCompleted(ip, result); }, Qt::QueuedConnection);
                continue;
            }

            SocketGuard sock;
            sock.socket = ::socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
            if (sock.socket == INVALID_SOCKET) {
                freeaddrinfo(addr);
                result.errorMessage = QStringLiteral("socket() failed");
                QMetaObject::invokeMethod(owner_, [owner = owner_, ip = task.ip, result]() { Q_EMIT owner->pingCompleted(ip, result); }, Qt::QueuedConnection);
                continue;
            }

            u_long nonBlocking = 1;
            ioctlsocket(sock.socket, FIONBIO, &nonBlocking);
            const int connectRc = ::connect(sock.socket, addr->ai_addr, static_cast<int>(addr->ai_addrlen));
            freeaddrinfo(addr);

            if (connectRc == 0) {
                result.timedOut = false;
                result.rttMs = static_cast<int>(QDateTime::currentMSecsSinceEpoch() - started);
                result.completedAtMs = QDateTime::currentMSecsSinceEpoch();
                QMetaObject::invokeMethod(owner_, [owner = owner_, ip = task.ip, result]() { Q_EMIT owner->pingCompleted(ip, result); }, Qt::QueuedConnection);
                continue;
            }

            fd_set writeSet;
            FD_ZERO(&writeSet);
            FD_SET(sock.socket, &writeSet);
            timeval tv{};
            tv.tv_sec = qBound(100, task.timeoutMs, 3000) / 1000;
            tv.tv_usec = (qBound(100, task.timeoutMs, 3000) % 1000) * 1000;
            const int sel = select(0, nullptr, &writeSet, nullptr, &tv);
            result.completedAtMs = QDateTime::currentMSecsSinceEpoch();
            if (sel <= 0) {
                result.timedOut = true;
                QMetaObject::invokeMethod(owner_, [owner = owner_, ip = task.ip, result]() { Q_EMIT owner->pingCompleted(ip, result); }, Qt::QueuedConnection);
                continue;
            }

            int soError = 0;
            int soLen = sizeof(soError);
            getsockopt(sock.socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soError), &soLen);
            if (soError == 0 || soError == WSAECONNREFUSED) {
                result.timedOut = false;
                result.rttMs = static_cast<int>(result.completedAtMs - started);
            } else {
                result.timedOut = true;
                result.errorMessage = QStringLiteral("connect failed %1").arg(soError);
            }
            QMetaObject::invokeMethod(owner_, [owner = owner_, ip = task.ip, result]() { Q_EMIT owner->pingCompleted(ip, result); }, Qt::QueuedConnection);
        }
    }

private:
    TcpPingProbeWin* owner_{nullptr};
    QMutex mutex_;
    QQueue<Task> queue_;
    std::atomic<bool> stop_{false};
};

} // namespace

struct TcpPingProbeWin::Impl {
    std::unique_ptr<Worker> worker;
};

TcpPingProbeWin::TcpPingProbeWin(QObject* parent)
    : QObject(parent)
    , impl_(std::make_unique<Impl>()) {}

TcpPingProbeWin::~TcpPingProbeWin() {
    stop();
}

void TcpPingProbeWin::start() {
    if (impl_->worker && impl_->worker->isRunning()) {
        return;
    }
    impl_->worker = std::make_unique<Worker>(this);
    impl_->worker->start();
}

void TcpPingProbeWin::stop() {
    if (!impl_->worker) {
        return;
    }
    impl_->worker->requestStop();
    impl_->worker->wait(1500);
    impl_->worker.reset();
}

void TcpPingProbeWin::enqueue(const QString& targetIp, const std::uint16_t port, const int timeoutMs) {
    if (!impl_->worker || !impl_->worker->isRunning()) {
        return;
    }
    impl_->worker->enqueue(Task{targetIp, port, timeoutMs});
}

} // namespace gpd::platform
