#include "core/ClashConnectionMatcher.h"

namespace gpd::core {

namespace {

QString processDestKey(const QString& processName, const QString& ip, const std::uint16_t port) {
    return QStringLiteral("%1|%2|%3").arg(processName.toLower(), ip, QString::number(port));
}

QString destKey(const QString& ip, const std::uint16_t port) {
    return QStringLiteral("%1|%2").arg(ip, QString::number(port));
}

} // namespace

void ClashConnectionMatcher::rebuildIndex(const ClashApiSnapshot& snapshot) {
    byProcessDestKey_.clear();
    byDestKey_.clear();
    for (const auto& conn : snapshot.connections) {
        if (!conn.destinationIp.isEmpty() && conn.destinationPort > 0) {
            byDestKey_.insert(destKey(conn.destinationIp, static_cast<std::uint16_t>(conn.destinationPort)), conn);
            if (!conn.processName.isEmpty()) {
                byProcessDestKey_.insert(processDestKey(conn.processName, conn.destinationIp, static_cast<std::uint16_t>(conn.destinationPort)), conn);
            }
        }
    }
}

std::optional<ClashConnectionMatcher::Match> ClashConnectionMatcher::findFor(const ConnectionInfo& conn) const {
    if (conn.remoteAddress.isEmpty() || conn.remotePort == 0) {
        return std::nullopt;
    }

    const auto byDest = byDestKey_.constFind(destKey(conn.remoteAddress, conn.remotePort));
    if (byDest == byDestKey_.cend()) {
        return std::nullopt;
    }

    Match out;
    out.outboundName = byDest->chains.isEmpty() ? QString() : byDest->chains[0];
    out.chains = byDest->chains;
    out.rule = byDest->rule;
    out.rulePayload = byDest->rulePayload;
    out.host = byDest->host;
    out.clashId = byDest->id;
    return out;
}

} // namespace gpd::core
