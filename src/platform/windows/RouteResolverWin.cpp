#include "platform/windows/RouteResolverWin.h"

#include <qt_windows.h>

#include <iphlpapi.h>
#include <ws2tcpip.h>

#include <memory>

namespace gpd::platform {

namespace {

QString ipv4ToString(const quint32 ipHostOrder) {
    IN_ADDR addr{};
    addr.S_un.S_addr = htonl(ipHostOrder);
    wchar_t buffer[INET_ADDRSTRLEN]{};
    if (InetNtopW(AF_INET, &addr, buffer, INET_ADDRSTRLEN) == nullptr) {
        return {};
    }
    return QString::fromWCharArray(buffer);
}

int prefixLengthFromMask(const quint32 maskHostOrder) {
    int bits = 0;
    quint32 m = maskHostOrder;
    while (m != 0) {
        bits += (m & 1U) != 0U ? 1 : 0;
        m >>= 1U;
    }
    return bits;
}

QString describeIpv4Route(const DWORD destinationNetworkOrder, const DWORD maskNetworkOrder, const DWORD nextHopNetworkOrder, const DWORD metric) {
    const quint32 dst = ntohl(destinationNetworkOrder);
    const quint32 mask = ntohl(maskNetworkOrder);
    const int prefix = prefixLengthFromMask(mask);
    const quint32 hop = ntohl(nextHopNetworkOrder);
    return QStringLiteral("prefix %1/%2, next hop %3, metric %4")
        .arg(ipv4ToString(dst))
        .arg(prefix)
        .arg(ipv4ToString(hop))
        .arg(metric);
}

} // namespace

std::optional<gpd::core::RoutingDecision> RouteResolverWin::resolveRouteFor(const QString& remoteIp) const {
    SOCKADDR_STORAGE storage{};

    SOCKADDR_IN addr4{};
    addr4.sin_family = AF_INET;
    if (InetPtonW(AF_INET, reinterpret_cast<LPCWSTR>(remoteIp.utf16()), &addr4.sin_addr) == 1) {
        memcpy(&storage, &addr4, sizeof(addr4));
    } else {
        SOCKADDR_IN6 addr6{};
        addr6.sin6_family = AF_INET6;
        if (InetPtonW(AF_INET6, reinterpret_cast<LPCWSTR>(remoteIp.utf16()), &addr6.sin6_addr) != 1) {
            return std::nullopt;
        }
        memcpy(&storage, &addr6, sizeof(addr6));
    }

    DWORD bestIfIndex = 0;
    const auto status = GetBestInterfaceEx(reinterpret_cast<sockaddr*>(&storage), &bestIfIndex);
    if (status != NO_ERROR || bestIfIndex == 0) {
        return std::nullopt;
    }

    gpd::core::RoutingDecision decision;
    decision.ifIndex = bestIfIndex;

    IN_ADDR remoteAddr4{};
    if (InetPtonW(AF_INET, reinterpret_cast<LPCWSTR>(remoteIp.utf16()), &remoteAddr4) == 1) {
        ULONG size = 0;
        if (GetIpForwardTable(nullptr, &size, FALSE) == ERROR_INSUFFICIENT_BUFFER && size >= sizeof(MIB_IPFORWARDTABLE)) {
            auto buffer = std::make_unique<unsigned char[]>(size);
            auto* table = reinterpret_cast<MIB_IPFORWARDTABLE*>(buffer.get());
            if (GetIpForwardTable(table, &size, FALSE) == NO_ERROR) {
                const quint32 remoteHostOrder = ntohl(remoteAddr4.S_un.S_addr);
                const MIB_IPFORWARDROW* bestRow = nullptr;
                int bestPrefix = -1;
                DWORD bestMetric = 0xFFFFFFFFUL;

                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    const auto& row = table->table[i];
                    if (row.dwForwardIfIndex != bestIfIndex) {
                        continue;
                    }
                    const quint32 mask = ntohl(row.dwForwardMask);
                    const quint32 net = ntohl(row.dwForwardDest);
                    if ((remoteHostOrder & mask) != (net & mask)) {
                        continue;
                    }
                    const int prefix = prefixLengthFromMask(mask);
                    if (prefix > bestPrefix || (prefix == bestPrefix && row.dwForwardMetric1 < bestMetric)) {
                        bestPrefix = prefix;
                        bestMetric = row.dwForwardMetric1;
                        bestRow = &row;
                    }
                }

                if (bestRow != nullptr) {
                    decision.reason = describeIpv4Route(bestRow->dwForwardDest,
                                                        bestRow->dwForwardMask,
                                                        bestRow->dwForwardNextHop,
                                                        bestRow->dwForwardMetric1);
                }
            }
        }
    }

    if (decision.reason.isEmpty()) {
        decision.reason = QStringLiteral("selected by system route lookup (best interface index %1)").arg(bestIfIndex);
    }
    return decision;
}

} // namespace gpd::platform
