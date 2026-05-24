#include "platform/windows/RouteHelpersWin.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <iphlpapi.h>
#include <netioapi.h>

#include <vector>

namespace {

QString sockaddrToString(const SOCKADDR* address) {
    if (address == nullptr) {
        return {};
    }
    wchar_t buffer[128]{};
    DWORD length = static_cast<DWORD>(std::size(buffer));
    int sockLen = 0;
    if (address->sa_family == AF_INET) {
        sockLen = sizeof(SOCKADDR_IN);
    } else if (address->sa_family == AF_INET6) {
        sockLen = sizeof(SOCKADDR_IN6);
    } else {
        return {};
    }
    if (WSAAddressToStringW(const_cast<LPSOCKADDR>(address), sockLen, nullptr, buffer, &length) != 0) {
        return {};
    }
    return QString::fromWCharArray(buffer);
}

bool isPhysicalAdapter(const IP_ADAPTER_ADDRESSES* adapter) {
    if (adapter == nullptr) {
        return false;
    }
    if (adapter->OperStatus != IfOperStatusUp) {
        return false;
    }
    if (adapter->IfType == IF_TYPE_TUNNEL || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
        return false;
    }
    if (adapter->TunnelType != TUNNEL_TYPE_NONE) {
        return false;
    }
    return true;
}

} // namespace

namespace gpd::platform {

QString findPhysicalDefaultGateway() {
    ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_ALL_INTERFACES;
    ULONG family = AF_INET;
    ULONG size = 0;
    if (GetAdaptersAddresses(family, flags, nullptr, nullptr, &size) != ERROR_BUFFER_OVERFLOW || size == 0) {
        return {};
    }
    std::vector<BYTE> buffer(size);
    auto* addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(family, flags, nullptr, addresses, &size) != NO_ERROR) {
        return {};
    }
    for (auto* adapter = addresses; adapter != nullptr; adapter = adapter->Next) {
        if (!isPhysicalAdapter(adapter)) {
            continue;
        }
        for (auto* gw = adapter->FirstGatewayAddress; gw != nullptr; gw = gw->Next) {
            const QString ip = sockaddrToString(gw->Address.lpSockaddr);
            if (!ip.isEmpty() && !ip.contains(QLatin1Char(':'))) {
                return ip;
            }
        }
    }
    return {};
}

QString findPhysicalLocalIPv4() {
    ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_ALL_INTERFACES;
    ULONG family = AF_INET;
    ULONG size = 0;
    if (GetAdaptersAddresses(family, flags, nullptr, nullptr, &size) != ERROR_BUFFER_OVERFLOW || size == 0) {
        return {};
    }
    std::vector<BYTE> buffer(size);
    auto* addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(family, flags, nullptr, addresses, &size) != NO_ERROR) {
        return {};
    }
    for (auto* adapter = addresses; adapter != nullptr; adapter = adapter->Next) {
        if (!isPhysicalAdapter(adapter)) {
            continue;
        }
        bool hasGateway = false;
        for (auto* gw = adapter->FirstGatewayAddress; gw != nullptr; gw = gw->Next) {
            if (gw->Address.lpSockaddr != nullptr && gw->Address.lpSockaddr->sa_family == AF_INET) {
                hasGateway = true;
                break;
            }
        }
        if (!hasGateway) {
            continue;
        }
        for (auto* unicast = adapter->FirstUnicastAddress; unicast != nullptr; unicast = unicast->Next) {
            if (unicast->Address.lpSockaddr == nullptr || unicast->Address.lpSockaddr->sa_family != AF_INET) {
                continue;
            }
            const QString ip = sockaddrToString(unicast->Address.lpSockaddr);
            if (!ip.isEmpty()) {
                return ip;
            }
        }
    }
    return {};
}

namespace {

bool nameLooksLikeTunnel(const QString& combined) {
    static const QStringList kTunnelMarkers = {
        QStringLiteral("wintun"), QStringLiteral("wireguard"), QStringLiteral("tailscale"),
        QStringLiteral("openvpn"), QStringLiteral("tap-windows"), QStringLiteral("tap0901"),
        QStringLiteral("nekobox"), QStringLiteral("sing-box"), QStringLiteral("singbox"),
        QStringLiteral("outline"), QStringLiteral("hiddify"), QStringLiteral("v2ray"),
        QStringLiteral("xray"), QStringLiteral("clash"), QStringLiteral("mullvad"),
        QStringLiteral("protonvpn"), QStringLiteral("nordlynx"), QStringLiteral("expressvpn"),
    };
    const QString lower = combined.toLower();
    for (const auto& marker : kTunnelMarkers) {
        if (lower.contains(marker)) {
            return true;
        }
    }
    return false;
}

TunnelStats aggregateStatsFiltered(const bool wantPhysical) {
    TunnelStats agg;
    ULONG flags = GAA_FLAG_INCLUDE_ALL_INTERFACES;
    ULONG family = AF_UNSPEC;
    ULONG size = 0;
    if (GetAdaptersAddresses(family, flags, nullptr, nullptr, &size) != ERROR_BUFFER_OVERFLOW || size == 0) {
        return agg;
    }
    std::vector<BYTE> buffer(size);
    auto* addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(family, flags, nullptr, addresses, &size) != NO_ERROR) {
        return agg;
    }
    for (auto* adapter = addresses; adapter != nullptr; adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp) {
            continue;
        }
        const QString friendly = adapter->FriendlyName != nullptr ? QString::fromWCharArray(adapter->FriendlyName) : QString();
        const QString description = adapter->Description != nullptr ? QString::fromWCharArray(adapter->Description) : QString();
        const QString combined = friendly + QLatin1Char(' ') + description;
        const bool isTunnel = adapter->IfType == IF_TYPE_TUNNEL || adapter->TunnelType != TUNNEL_TYPE_NONE || nameLooksLikeTunnel(combined);
        const bool isLoopback = adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK;
        bool hasGateway = false;
        for (auto* gw = adapter->FirstGatewayAddress; gw != nullptr; gw = gw->Next) {
            if (gw->Address.lpSockaddr != nullptr) {
                hasGateway = true;
                break;
            }
        }
        const bool isPhysical = !isTunnel && !isLoopback && hasGateway;
        if (wantPhysical && !isPhysical) {
            continue;
        }
        if (!wantPhysical && !isTunnel) {
            continue;
        }
        MIB_IF_ROW2 row{};
        row.InterfaceLuid = adapter->Luid;
        if (GetIfEntry2(&row) != NO_ERROR) {
            continue;
        }
        if (!agg.found) {
            agg.found = true;
            agg.friendlyName = friendly;
            agg.ifIndex = adapter->IfIndex;
        }
        agg.inOctets += row.InOctets;
        agg.outOctets += row.OutOctets;
    }
    return agg;
}

} // namespace

TunnelStats aggregateTunnelStats() {
    return aggregateStatsFiltered(false);
}

TunnelStats aggregatePhysicalStats() {
    return aggregateStatsFiltered(true);
}

} // namespace gpd::platform
