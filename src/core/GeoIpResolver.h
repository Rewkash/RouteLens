#pragma once

#include "core/Models.h"

#include <QHash>
#include <QMutex>
#include <QObject>
#include <QString>
#include <QStringList>

#include <memory>

namespace gpd::core {

class GeoIpResolver final : public QObject {
    Q_OBJECT
public:
    explicit GeoIpResolver(QObject* parent = nullptr);
    ~GeoIpResolver() override;

    [[nodiscard]] bool open(const QString& countryDbPath, const QString& asnDbPath);
    void close();

    [[nodiscard]] bool isReady() const noexcept;
    [[nodiscard]] GeoInfo lookup(const QString& ipAddress) const;
    [[nodiscard]] QHash<QString, GeoInfo> lookupBatch(const QStringList& ipAddresses) const;

    [[nodiscard]] static QString defaultGeoDirectory();
    void setOnlineFallbackEnabled(bool enabled) noexcept;

Q_SIGNALS:
    void statusChanged(bool ready);

private:
    struct CacheEntry {
        GeoInfo info;
        qint64 expiresAtMs{0};
    };

    struct Impl;
    mutable QMutex mutex_;
    std::unique_ptr<Impl> impl_;
    mutable QHash<QString, CacheEntry> cache_;
    bool onlineFallbackEnabled_{true};
};

} // namespace gpd::core
