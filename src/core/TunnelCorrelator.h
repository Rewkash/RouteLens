#pragma once

#include "core/Models.h"

#include <QHash>
#include <QSet>
#include <QMutex>

#include <cstdint>

namespace gpd::core {

struct TunnelActivityKey {
    std::uint32_t tunnelPid{0};
    std::uint32_t physIfIndex{0};

    bool operator==(const TunnelActivityKey& other) const noexcept {
        return tunnelPid == other.tunnelPid && physIfIndex == other.physIfIndex;
    }
};

struct TunnelActivityWindow {
    std::int64_t firstSeenMs{0};
    std::int64_t lastSeenMs{0};
    std::uint64_t bytesSent{0};
    std::uint64_t bytesRecv{0};
    std::uint64_t packets{0};
    QString tunnelProcessName;
};

class TunnelCorrelator final {
public:
    explicit TunnelCorrelator(int windowMs = 2000);

    void registerTunnelProcess(std::uint32_t pid, const QString& processName);
    void unregisterTunnelProcess(std::uint32_t pid);
    void recordFlow(std::uint32_t pid,
                    std::uint32_t ifIndex,
                    InterfaceKind ifKind,
                    std::uint32_t bytes,
                    bool isSent,
                    std::int64_t timestampMs,
                    const QString& remoteAddress);
    [[nodiscard]] QString hasActiveTunnel(std::int64_t nowMs, int windowMsOverride = -1, std::uint64_t minBytesInWindow = 512) const;
    [[nodiscard]] bool hasRecentTunnelRemote(const QString& remoteAddress, std::int64_t nowMs, int windowMsOverride = -1) const;
    [[nodiscard]] bool hasRecentDifferentTunnelRemote(const QString& remoteAddress, std::int64_t nowMs, int windowMsOverride = -1) const;
    [[nodiscard]] QHash<std::uint32_t, TunnelActivityWindow> snapshot(std::int64_t nowMs) const;
    void prune(std::int64_t cutoffMs);

private:
    mutable QMutex mutex_;
    int windowMs_;
    QHash<std::uint32_t, QString> registeredTunnels_;
    QHash<TunnelActivityKey, TunnelActivityWindow> activity_;
    QHash<QString, std::int64_t> remoteLastSeenMs_;
};

} // namespace gpd::core

namespace gpd::core {

inline size_t qHash(const TunnelActivityKey& key, const size_t seed = 0) noexcept {
    return ::qHash(key.tunnelPid, seed) ^ ::qHash(key.physIfIndex, seed);
}

} // namespace gpd::core
