#include "core/diagnostic/BufferbloatProbe.h"

#include "core/PingScheduler.h"

#include <QDateTime>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTimer>

namespace gpd::core {

namespace {

QString pingKey(const QString& ip, const QString& localAddress) {
    return QStringLiteral("%1|%2").arg(ip, localAddress);
}

double targetRttMs(PingScheduler* scheduler, const QString& ip, const QString& localAddress) {
    if (scheduler == nullptr || ip.isEmpty()) {
        return 0.0;
    }
    const auto snap = scheduler->snapshot();
    const auto agg = snap.value(pingKey(ip, localAddress));
    return agg.rttAvgMs > 0 ? static_cast<double>(agg.rttAvgMs) : 0.0;
}

} // namespace

BufferbloatProbe::BufferbloatProbe(PingScheduler* scheduler, QObject* parent)
    : QObject(parent)
    , scheduler_(scheduler)
    , network_(new QNetworkAccessManager(this)) {
}

void BufferbloatProbe::setTarget(const QString& ip, const QString& localAddress) {
    targetIp_ = ip;
    localAddress_ = localAddress;
}

void BufferbloatProbe::runTest(const int durationMs) {
    if (running_) {
        return;
    }
    durationMs_ = qMax(3000, durationMs);
    bytesDownloaded_ = 0;
    startedAtMs_ = QDateTime::currentMSecsSinceEpoch();

    const double idleRtt = targetRttMs(scheduler_, targetIp_, localAddress_);

    QNetworkRequest req(QUrl(QStringLiteral("https://speed.cloudflare.com/__down?bytes=104857600")));
    reply_ = network_->get(req);
    running_ = true;

    connect(reply_, &QNetworkReply::readyRead, this, [this]() {
        if (reply_ == nullptr) {
            return;
        }
        bytesDownloaded_ += reply_->readAll().size();
    });

    const auto finalize = [this, idleRtt]() {
        if (!running_) {
            return;
        }
        running_ = false;
        if (reply_ != nullptr) {
            reply_->abort();
            reply_->deleteLater();
            reply_ = nullptr;
        }
        const qint64 elapsedMs = qMax<qint64>(1, QDateTime::currentMSecsSinceEpoch() - startedAtMs_);
        const double loadedRtt = targetRttMs(scheduler_, targetIp_, localAddress_);
        const double mbits = (static_cast<double>(bytesDownloaded_) * 8.0) / (1000.0 * 1000.0);
        const double bwMbps = mbits / (static_cast<double>(elapsedMs) / 1000.0);

        QVariantMap s;
        s.insert(QStringLiteral("idleRttMs"), idleRtt);
        s.insert(QStringLiteral("loadedRttMs"), loadedRtt);
        s.insert(QStringLiteral("latencyIncrease"), loadedRtt - idleRtt);
        s.insert(QStringLiteral("downloadBwMbps"), bwMbps);
        lastSnapshot_ = s;
        Q_EMIT completed(lastSnapshot_);
    };

    connect(reply_, &QNetworkReply::finished, this, finalize);
    QTimer::singleShot(durationMs_, this, finalize);
}

QString BufferbloatProbe::probeId() const {
    return QStringLiteral("bufferbloat");
}

bool BufferbloatProbe::start() {
    return true;
}

void BufferbloatProbe::stop() {
    if (reply_ != nullptr) {
        reply_->abort();
        reply_->deleteLater();
        reply_ = nullptr;
    }
    running_ = false;
}

QVariantMap BufferbloatProbe::snapshot() const {
    return lastSnapshot_;
}

} // namespace gpd::core
