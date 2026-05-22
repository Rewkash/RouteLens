#pragma once

#include "core/Models.h"

#include <QJsonObject>
#include <QMutex>
#include <QObject>
#include <QNetworkRequest>
#include <QUrl>
#include <QVector>

#include <memory>
#include <optional>

class QNetworkAccessManager;
class QNetworkReply;
class QTimer;

namespace gpd::core {

struct ClashConnection {
    QString id;
    QString networkProtocol;
    QString destinationIp;
    int destinationPort{0};
    QString sourceIp;
    int sourcePort{0};
    QString host;
    QString processName;
    QString processPath;
    std::int64_t uploadBytes{0};
    std::int64_t downloadBytes{0};
    std::int64_t createdAtMs{0};
    QVector<QString> chains;
    QString rule;
    QString rulePayload;
};

enum class ClashApiStatus {
    Disabled,
    Probing,
    Connecting,
    Connected,
    Unreachable,
    AuthFailed,
    InvalidResponse,
};

struct ClashApiSnapshot {
    QVector<ClashConnection> connections;
    std::int64_t fetchedAtMs{0};
};

class ClashApiClient final : public QObject {
    Q_OBJECT

public:
    explicit ClashApiClient(QObject* parent = nullptr);
    ~ClashApiClient() override;

    void configure(const QUrl& baseUrl, const QString& secret);
    void start(int pollIntervalMs = 1000);
    void stop();
    void probeNow();

    [[nodiscard]] ClashApiStatus status() const noexcept;
    [[nodiscard]] QString lastErrorMessage() const;
    [[nodiscard]] ClashApiSnapshot currentSnapshot() const;

    [[nodiscard]] static std::optional<ClashConnection> parseConnection(const QJsonObject& obj);

Q_SIGNALS:
    void statusChanged(gpd::core::ClashApiStatus newStatus);
    void snapshotUpdated(const gpd::core::ClashApiSnapshot& snapshot);

private:
    void pollOnce();
    void handleVersionReply(QNetworkReply* reply);
    void handleConnectionsReply(QNetworkReply* reply);
    void applyAuth(QNetworkRequest& request) const;
    void setStatus(ClashApiStatus newStatus, const QString& errorOpt = QString());

    std::unique_ptr<QNetworkAccessManager> network_;
    QTimer* pollTimer_{nullptr};
    QUrl baseUrl_;
    QString secret_;
    QString cachedError_;
    ClashApiStatus status_{ClashApiStatus::Disabled};
    ClashApiSnapshot snapshot_;
    mutable QMutex snapshotMutex_;
};

} // namespace gpd::core

Q_DECLARE_METATYPE(gpd::core::ClashApiSnapshot)
Q_DECLARE_METATYPE(gpd::core::ClashApiStatus)
