#include "core/ClashApiClient.h"

#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTimer>

namespace gpd::core {

namespace {

QString baseNameLower(const QString& processPath, const QString& processName) {
    if (!processName.isEmpty()) {
        return processName.toLower();
    }
    QString value = processPath;
    const int slashPos = qMax(value.lastIndexOf(QLatin1Char('/')), value.lastIndexOf(QLatin1Char('\\')));
    if (slashPos >= 0 && slashPos + 1 < value.size()) {
        value = value.mid(slashPos + 1);
    }
    return value.toLower();
}

} // namespace

ClashApiClient::ClashApiClient(QObject* parent)
    : QObject(parent)
    , network_(std::make_unique<QNetworkAccessManager>(this))
    , pollTimer_(new QTimer(this)) {
    qRegisterMetaType<gpd::core::ClashApiSnapshot>("gpd::core::ClashApiSnapshot");
    qRegisterMetaType<gpd::core::ClashApiStatus>("gpd::core::ClashApiStatus");
    connect(pollTimer_, &QTimer::timeout, this, [this]() { pollOnce(); });
}

ClashApiClient::~ClashApiClient() {
    stop();
}

void ClashApiClient::configure(const QUrl& baseUrl, const QString& secret) {
    baseUrl_ = baseUrl;
    secret_ = secret;
    if (!baseUrl_.isValid() || baseUrl_.isEmpty()) {
        stop();
        setStatus(ClashApiStatus::Disabled);
    }
}

void ClashApiClient::start(const int pollIntervalMs) {
    if (!baseUrl_.isValid() || baseUrl_.isEmpty()) {
        setStatus(ClashApiStatus::Disabled);
        return;
    }
    pollTimer_->start(qMax(300, pollIntervalMs));
    setStatus(ClashApiStatus::Connecting);
    probeNow();
    pollOnce();
}

void ClashApiClient::stop() {
    pollTimer_->stop();
}

void ClashApiClient::probeNow() {
    if (!baseUrl_.isValid() || baseUrl_.isEmpty()) {
        setStatus(ClashApiStatus::Disabled);
        return;
    }
    QNetworkRequest request(baseUrl_.resolved(QUrl(QStringLiteral("/version"))));
    request.setTransferTimeout(5000);
    applyAuth(request);
    setStatus(ClashApiStatus::Probing);
    auto* reply = network_->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() { handleVersionReply(reply); });
}

ClashApiStatus ClashApiClient::status() const noexcept {
    return status_;
}

QString ClashApiClient::lastErrorMessage() const {
    return cachedError_;
}

ClashApiSnapshot ClashApiClient::currentSnapshot() const {
    QMutexLocker locker(&snapshotMutex_);
    return snapshot_;
}

std::optional<ClashConnection> ClashApiClient::parseConnection(const QJsonObject& obj) {
    ClashConnection out;
    out.id = obj.value(QStringLiteral("id")).toString();
    const auto metadataValue = obj.value(QStringLiteral("metadata"));
    const QJsonObject metadata = metadataValue.isObject() ? metadataValue.toObject() : QJsonObject();
    out.networkProtocol = metadata.value(QStringLiteral("network")).toString().toLower();
    out.destinationIp = metadata.value(QStringLiteral("destinationIP")).toString();
    out.destinationPort = metadata.value(QStringLiteral("destinationPort")).toVariant().toInt();
    out.sourceIp = metadata.value(QStringLiteral("sourceIP")).toString();
    out.sourcePort = metadata.value(QStringLiteral("sourcePort")).toVariant().toInt();
    out.host = metadata.value(QStringLiteral("host")).toString();
    out.processPath = metadata.value(QStringLiteral("processPath")).toString();
    out.processName = baseNameLower(out.processPath, metadata.value(QStringLiteral("process")).toString());
    out.uploadBytes = static_cast<std::int64_t>(obj.value(QStringLiteral("upload")).toDouble());
    out.downloadBytes = static_cast<std::int64_t>(obj.value(QStringLiteral("download")).toDouble());
    out.rule = obj.value(QStringLiteral("rule")).toString();
    out.rulePayload = obj.value(QStringLiteral("rulePayload")).toString();

    const auto chainsValue = obj.value(QStringLiteral("chains"));
    if (chainsValue.isArray()) {
        const auto chainArray = chainsValue.toArray();
        out.chains.reserve(chainArray.size());
        for (const auto& item : chainArray) {
            out.chains.push_back(item.toString());
        }
    } else {
        const auto outbound = obj.value(QStringLiteral("outbound")).toString();
        if (!outbound.isEmpty()) {
            out.chains.push_back(outbound);
        }
    }

    if (out.destinationIp.isEmpty() && out.host.isEmpty()) {
        return std::nullopt;
    }
    return out;
}

void ClashApiClient::pollOnce() {
    if (!baseUrl_.isValid() || baseUrl_.isEmpty()) {
        return;
    }
    QNetworkRequest request(baseUrl_.resolved(QUrl(QStringLiteral("/connections"))));
    request.setTransferTimeout(5000);
    applyAuth(request);
    auto* reply = network_->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() { handleConnectionsReply(reply); });
}

void ClashApiClient::handleVersionReply(QNetworkReply* reply) {
    const auto statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const auto payload = reply->readAll();
    const auto error = reply->error();
    reply->deleteLater();

    if (statusCode == 401) {
        setStatus(ClashApiStatus::AuthFailed, QStringLiteral("Clash API auth failed (401)"));
        return;
    }
    if (error != QNetworkReply::NoError) {
        setStatus(ClashApiStatus::Unreachable, QStringLiteral("Clash API unreachable"));
        return;
    }

    QJsonParseError parseError;
    const auto doc = QJsonDocument::fromJson(payload, &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        setStatus(ClashApiStatus::InvalidResponse, QStringLiteral("Invalid /version response"));
        return;
    }

    setStatus(ClashApiStatus::Connected);
}

void ClashApiClient::handleConnectionsReply(QNetworkReply* reply) {
    const auto statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const auto payload = reply->readAll();
    const auto error = reply->error();
    reply->deleteLater();

    if (statusCode == 401) {
        setStatus(ClashApiStatus::AuthFailed, QStringLiteral("Clash API auth failed (401)"));
        return;
    }
    if (error != QNetworkReply::NoError) {
        setStatus(ClashApiStatus::Unreachable, QStringLiteral("Clash API unreachable"));
        return;
    }

    QJsonParseError parseError;
    const auto doc = QJsonDocument::fromJson(payload, &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        setStatus(ClashApiStatus::InvalidResponse, QStringLiteral("Invalid /connections response"));
        return;
    }

    ClashApiSnapshot snap;
    snap.fetchedAtMs = QDateTime::currentMSecsSinceEpoch();
    const auto arr = doc.object().value(QStringLiteral("connections")).toArray();
    snap.connections.reserve(arr.size());
    for (const auto& item : arr) {
        if (!item.isObject()) {
            continue;
        }
        const auto parsed = parseConnection(item.toObject());
        if (parsed.has_value()) {
            snap.connections.push_back(*parsed);
        }
    }

    {
        QMutexLocker locker(&snapshotMutex_);
        snapshot_ = snap;
    }
    setStatus(ClashApiStatus::Connected);
    Q_EMIT snapshotUpdated(snap);
}

void ClashApiClient::applyAuth(QNetworkRequest& request) const {
    if (secret_.isEmpty()) {
        return;
    }
    request.setRawHeader("Authorization", QStringLiteral("Bearer %1").arg(secret_).toUtf8());
}

void ClashApiClient::setStatus(const ClashApiStatus newStatus, const QString& errorOpt) {
    cachedError_ = errorOpt;
    if (status_ == newStatus) {
        return;
    }
    status_ = newStatus;
    Q_EMIT statusChanged(status_);
}

} // namespace gpd::core
