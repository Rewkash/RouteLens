#include "core/TunnelCorrelator.h"

#include <QMutexLocker>

namespace gpd::core {

namespace {

bool isPhysical(const InterfaceKind kind) {
    return kind == InterfaceKind::Ethernet || kind == InterfaceKind::WiFi || kind == InterfaceKind::Cellular;
}

} // namespace

TunnelCorrelator::TunnelCorrelator(const int windowMs)
    : windowMs_(qMax(250, windowMs)) {}

void TunnelCorrelator::registerTunnelProcess(const std::uint32_t pid, const QString& processName) {
    QMutexLocker locker(&mutex_);
    registeredTunnels_.insert(pid, processName.toLower());
}

void TunnelCorrelator::unregisterTunnelProcess(const std::uint32_t pid) {
    QMutexLocker locker(&mutex_);
    registeredTunnels_.remove(pid);
    auto it = activity_.begin();
    while (it != activity_.end()) {
        if (it.key().tunnelPid == pid) {
            it = activity_.erase(it);
        } else {
            ++it;
        }
    }
}

void TunnelCorrelator::recordFlow(const std::uint32_t pid,
                                  const std::uint32_t ifIndex,
                                  const InterfaceKind ifKind,
                                  const std::uint32_t bytes,
                                  const bool isSent,
                                  const std::int64_t timestampMs,
                                  const QString& remoteAddress) {
    if (!isPhysical(ifKind) || ifIndex == 0 || timestampMs <= 0) {
        return;
    }

    QMutexLocker locker(&mutex_);
    const auto tunnelIt = registeredTunnels_.constFind(pid);
    if (tunnelIt == registeredTunnels_.cend()) {
        return;
    }

    TunnelActivityKey key;
    key.tunnelPid = pid;
    key.physIfIndex = ifIndex;
    auto& item = activity_[key];
    if (item.firstSeenMs == 0) {
        item.firstSeenMs = timestampMs;
    }
    item.lastSeenMs = timestampMs;
    item.packets += 1;
    if (isSent) {
        item.bytesSent += bytes;
    } else {
        item.bytesRecv += bytes;
    }
    item.tunnelProcessName = tunnelIt.value();
    if (!remoteAddress.isEmpty()) {
        remoteLastSeenMs_.insert(remoteAddress, timestampMs);
    }
}

QString TunnelCorrelator::hasActiveTunnel(const std::int64_t nowMs, const int windowMsOverride, const std::uint64_t minBytesInWindow) const {
    QMutexLocker locker(&mutex_);
    const int activeWindow = windowMsOverride > 0 ? windowMsOverride : windowMs_;
    std::uint64_t bestBytes = 0;
    QString bestName;
    for (auto it = activity_.cbegin(); it != activity_.cend(); ++it) {
        const auto& item = it.value();
        if ((nowMs - item.lastSeenMs) > activeWindow) {
            continue;
        }
        const std::uint64_t totalBytes = item.bytesSent + item.bytesRecv;
        if (totalBytes < minBytesInWindow) {
            continue;
        }
        if (totalBytes > bestBytes) {
            bestBytes = totalBytes;
            bestName = item.tunnelProcessName;
        }
    }
    return bestName;
}

bool TunnelCorrelator::hasRecentTunnelRemote(const QString& remoteAddress, const std::int64_t nowMs, const int windowMsOverride) const {
    if (remoteAddress.isEmpty()) {
        return false;
    }
    QMutexLocker locker(&mutex_);
    const int activeWindow = windowMsOverride > 0 ? windowMsOverride : windowMs_;
    const auto it = remoteLastSeenMs_.constFind(remoteAddress);
    if (it == remoteLastSeenMs_.cend()) {
        return false;
    }
    return (nowMs - it.value()) <= activeWindow;
}

bool TunnelCorrelator::hasRecentDifferentTunnelRemote(const QString& remoteAddress, const std::int64_t nowMs, const int windowMsOverride) const {
    QMutexLocker locker(&mutex_);
    const int activeWindow = windowMsOverride > 0 ? windowMsOverride : windowMs_;
    for (auto it = remoteLastSeenMs_.cbegin(); it != remoteLastSeenMs_.cend(); ++it) {
        if ((nowMs - it.value()) > activeWindow) {
            continue;
        }
        if (it.key() != remoteAddress) {
            return true;
        }
    }
    return false;
}

QHash<std::uint32_t, TunnelActivityWindow> TunnelCorrelator::snapshot(const std::int64_t nowMs) const {
    QHash<std::uint32_t, TunnelActivityWindow> out;
    QMutexLocker locker(&mutex_);
    for (auto it = activity_.cbegin(); it != activity_.cend(); ++it) {
        const auto& key = it.key();
        const auto& item = it.value();
        if ((nowMs - item.lastSeenMs) > windowMs_) {
            continue;
        }
        const auto existing = out.constFind(key.tunnelPid);
        if (existing == out.cend() || (item.bytesSent + item.bytesRecv) > (existing->bytesSent + existing->bytesRecv)) {
            out.insert(key.tunnelPid, item);
        }
    }
    return out;
}

void TunnelCorrelator::prune(const std::int64_t cutoffMs) {
    QMutexLocker locker(&mutex_);
    auto it = activity_.begin();
    while (it != activity_.end()) {
        if (it.value().lastSeenMs < cutoffMs) {
            it = activity_.erase(it);
        } else {
            ++it;
        }
    }
    auto remoteIt = remoteLastSeenMs_.begin();
    while (remoteIt != remoteLastSeenMs_.end()) {
        if (remoteIt.value() < cutoffMs) {
            remoteIt = remoteLastSeenMs_.erase(remoteIt);
        } else {
            ++remoteIt;
        }
    }
}

} // namespace gpd::core
