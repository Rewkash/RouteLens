#include "core/GeoIpResolver.h"

#include "core/RouteClassifier.h"

#include <QDateTime>
#include <QDir>
#include <QEventLoop>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMutexLocker>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QStandardPaths>
#include <QUrl>

#if defined(GPD_HAS_MAXMINDDB)
#include <maxminddb.h>
#endif

#include <ws2tcpip.h>

namespace {

constexpr qint64 kResolvedTtlMs = 24LL * 60LL * 60LL * 1000LL;
constexpr qint64 kMissTtlMs = 5LL * 60LL * 1000LL;

#if defined(GPD_HAS_MAXMINDDB)
QString fromMmdbUtf8(const MMDB_entry_data_s& entry) {
    if (!entry.has_data || entry.type != MMDB_DATA_TYPE_UTF8_STRING || entry.utf8_string == nullptr || entry.data_size <= 0) {
        return {};
    }
    return QString::fromUtf8(entry.utf8_string, static_cast<int>(entry.data_size));
}
#endif

} // namespace

namespace gpd::core {

struct GeoIpResolver::Impl {
#if defined(GPD_HAS_MAXMINDDB)
    MMDB_s country{};
    MMDB_s asn{};
    bool countryOpen{false};
    bool asnOpen{false};
#else
    std::unique_ptr<QNetworkAccessManager> nam;
#endif
};

GeoIpResolver::GeoIpResolver(QObject* parent)
    : QObject(parent)
    , impl_(std::make_unique<Impl>()) {
#if !defined(GPD_HAS_MAXMINDDB)
    impl_->nam = std::make_unique<QNetworkAccessManager>();
#endif
}

GeoIpResolver::~GeoIpResolver() {
    close();
}

bool GeoIpResolver::open(const QString& countryDbPath, const QString& asnDbPath) {
    Q_UNUSED(countryDbPath)
    Q_UNUSED(asnDbPath)
#if !defined(GPD_HAS_MAXMINDDB)
    Q_EMIT statusChanged(false);
    return false;
#else
    QMutexLocker lock(&mutex_);
    if (impl_->countryOpen) {
        MMDB_close(&impl_->country);
        impl_->countryOpen = false;
    }
    if (impl_->asnOpen) {
        MMDB_close(&impl_->asn);
        impl_->asnOpen = false;
    }

    const QByteArray countryPath = QDir::toNativeSeparators(countryDbPath).toUtf8();
    const QByteArray asnPath = QDir::toNativeSeparators(asnDbPath).toUtf8();

    impl_->countryOpen = MMDB_open(countryPath.constData(), MMDB_MODE_MMAP, &impl_->country) == MMDB_SUCCESS;
    impl_->asnOpen = MMDB_open(asnPath.constData(), MMDB_MODE_MMAP, &impl_->asn) == MMDB_SUCCESS;
    cache_.clear();

    const bool ready = impl_->countryOpen && impl_->asnOpen;
    Q_EMIT statusChanged(ready);
    return ready;
#endif
}

void GeoIpResolver::close() {
#if defined(GPD_HAS_MAXMINDDB)
    QMutexLocker lock(&mutex_);
    if (impl_->countryOpen) {
        MMDB_close(&impl_->country);
        impl_->countryOpen = false;
    }
    if (impl_->asnOpen) {
        MMDB_close(&impl_->asn);
        impl_->asnOpen = false;
    }
    cache_.clear();
#endif
}

bool GeoIpResolver::isReady() const noexcept {
#if !defined(GPD_HAS_MAXMINDDB)
    QMutexLocker lock(&mutex_);
    return onlineFallbackEnabled_ && impl_->nam != nullptr;
#else
    QMutexLocker lock(&mutex_);
    return impl_->countryOpen && impl_->asnOpen;
#endif
}

GeoInfo GeoIpResolver::lookup(const QString& ipAddress) const {
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    {
        QMutexLocker lock(&mutex_);
        const auto it = cache_.constFind(ipAddress);
        if (it != cache_.cend() && it->expiresAtMs > nowMs) {
            return it->info;
        }
    }

    GeoInfo info;
    if (RouteClassifier::isPrivateAddress(ipAddress)) {
        info.isPrivate = true;
        info.resolved = true;
    }

#if !defined(GPD_HAS_MAXMINDDB)
    if (!onlineFallbackEnabled_ || impl_->nam == nullptr) {
        QMutexLocker lock(&mutex_);
        cache_.insert(ipAddress, CacheEntry{info, nowMs + (info.isPrivate ? kResolvedTtlMs : kMissTtlMs)});
        return info;
    }

    QNetworkRequest request(QUrl(QStringLiteral("https://ipwho.is/%1").arg(ipAddress)));
    request.setTransferTimeout(1500);
    auto* reply = impl_->nam->get(request);
    QEventLoop loop;
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();

    if (reply->error() == QNetworkReply::NoError) {
        const auto doc = QJsonDocument::fromJson(reply->readAll());
        const QJsonObject root = doc.object();
        if (root.value(QStringLiteral("success")).toBool()) {
            info.countryIsoCode = root.value(QStringLiteral("country_code")).toString();
            info.countryName = root.value(QStringLiteral("country")).toString();
            const QJsonObject connection = root.value(QStringLiteral("connection")).toObject();
            const int asn = connection.value(QStringLiteral("asn")).toInt();
            if (asn > 0) {
                info.asnNumber = QStringLiteral("AS%1").arg(asn);
            }
            info.asnOrganization = connection.value(QStringLiteral("org")).toString();
            info.resolved = !info.countryIsoCode.isEmpty() || !info.asnNumber.isEmpty();
        }
    }
    reply->deleteLater();

    QMutexLocker lock(&mutex_);
    cache_.insert(ipAddress, CacheEntry{info, nowMs + ((info.resolved || info.isPrivate) ? kResolvedTtlMs : kMissTtlMs)});
    return info;
#else
    sockaddr_storage storage{};
    addrinfo hints{};
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    addrinfo* result = nullptr;
    const QByteArray ip = ipAddress.toUtf8();
    if (getaddrinfo(ip.constData(), "0", &hints, &result) != 0 || result == nullptr) {
        QMutexLocker lock(&mutex_);
        cache_.insert(ipAddress, CacheEntry{info, nowMs + kMissTtlMs});
        return info;
    }

    memcpy(&storage, result->ai_addr, static_cast<size_t>(result->ai_addrlen));
    freeaddrinfo(result);

    QMutexLocker lock(&mutex_);
    if (!(impl_->countryOpen && impl_->asnOpen) || info.isPrivate) {
        cache_.insert(ipAddress, CacheEntry{info, nowMs + (info.isPrivate ? kResolvedTtlMs : kMissTtlMs)});
        return info;
    }

    int gaiError = 0;
    int mmdbError = MMDB_SUCCESS;

    const auto countryLookup = MMDB_lookup_sockaddr(&impl_->country, reinterpret_cast<const sockaddr*>(&storage), &gaiError, &mmdbError);
    if (gaiError == 0 && mmdbError == MMDB_SUCCESS && countryLookup.found_entry != 0) {
        MMDB_entry_data_s countryCode{};
        if (MMDB_get_value(&countryLookup.entry, &countryCode, "country", "iso_code", nullptr) == MMDB_SUCCESS) {
            info.countryIsoCode = fromMmdbUtf8(countryCode);
        }
        MMDB_entry_data_s countryName{};
        if (MMDB_get_value(&countryLookup.entry, &countryName, "country", "names", "en", nullptr) == MMDB_SUCCESS) {
            info.countryName = fromMmdbUtf8(countryName);
        }
    }

    const auto asnLookup = MMDB_lookup_sockaddr(&impl_->asn, reinterpret_cast<const sockaddr*>(&storage), &gaiError, &mmdbError);
    if (gaiError == 0 && mmdbError == MMDB_SUCCESS && asnLookup.found_entry != 0) {
        MMDB_entry_data_s asnNumber{};
        if (MMDB_get_value(&asnLookup.entry, &asnNumber, "autonomous_system_number", nullptr) == MMDB_SUCCESS && asnNumber.has_data &&
            (asnNumber.type == MMDB_DATA_TYPE_UINT32 || asnNumber.type == MMDB_DATA_TYPE_UINT16)) {
            const quint32 n = asnNumber.type == MMDB_DATA_TYPE_UINT16 ? static_cast<quint32>(asnNumber.uint16) : asnNumber.uint32;
            info.asnNumber = QStringLiteral("AS%1").arg(n);
        }
        MMDB_entry_data_s asnOrg{};
        if (MMDB_get_value(&asnLookup.entry, &asnOrg, "autonomous_system_organization", nullptr) == MMDB_SUCCESS) {
            info.asnOrganization = fromMmdbUtf8(asnOrg);
        }
    }

    info.resolved = !info.countryIsoCode.isEmpty() || !info.countryName.isEmpty() || !info.asnNumber.isEmpty() || !info.asnOrganization.isEmpty();
    cache_.insert(ipAddress, CacheEntry{info, nowMs + (info.resolved ? kResolvedTtlMs : kMissTtlMs)});
    return info;
#endif
}

QHash<QString, GeoInfo> GeoIpResolver::lookupBatch(const QStringList& ipAddresses) const {
    QHash<QString, GeoInfo> result;
    result.reserve(ipAddresses.size());
    for (const auto& ip : ipAddresses) {
        result.insert(ip, lookup(ip));
    }
    return result;
}

void GeoIpResolver::setOnlineFallbackEnabled(const bool enabled) noexcept {
    QMutexLocker lock(&mutex_);
    onlineFallbackEnabled_ = enabled;
}

QString GeoIpResolver::defaultGeoDirectory() {
    const QString appData = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir dir(appData);
    dir.mkpath(QStringLiteral("geoip"));
    return dir.filePath(QStringLiteral("geoip"));
}

} // namespace gpd::core
