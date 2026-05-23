#include "platform/windows/diagnostic/VpnRouteProbe.h"

#include "core/InterfaceClassifier.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <iphlpapi.h>
#include <netioapi.h>

#include <vector>

namespace {

QString sockaddrToIp(const SOCKADDR_INET& address) {
    wchar_t buffer[128]{};
    const auto* raw = reinterpret_cast<const SOCKADDR*>(&address);
    const int sockLen = address.si_family == AF_INET ? static_cast<int>(sizeof(SOCKADDR_IN)) : static_cast<int>(sizeof(SOCKADDR_IN6));
    DWORD length = static_cast<DWORD>(std::size(buffer));
    if (WSAAddressToStringW(const_cast<LPSOCKADDR>(raw), sockLen, nullptr, buffer, &length) != 0) {
        return {};
    }
    return QString::fromWCharArray(buffer);
}

QHash<quint32, gpd::core::InterfaceKind> interfaceKindsByIndex() {
    QHash<quint32, gpd::core::InterfaceKind> out;
    ULONG flags = GAA_FLAG_INCLUDE_ALL_INTERFACES;
    ULONG family = AF_UNSPEC;
    ULONG size = 0;
    if (GetAdaptersAddresses(family, flags, nullptr, nullptr, &size) != ERROR_BUFFER_OVERFLOW || size == 0) {
        return out;
    }
    std::vector<BYTE> buffer(size);
    auto* addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(family, flags, nullptr, addresses, &size) != NO_ERROR) {
        return out;
    }
    for (auto* adapter = addresses; adapter != nullptr; adapter = adapter->Next) {
        gpd::core::NetworkInterfaceInfo info;
        info.ifIndex = adapter->IfIndex;
        info.ifType = adapter->IfType;
        info.tunnelType = adapter->TunnelType;
        info.friendlyName = adapter->FriendlyName != nullptr ? QString::fromWCharArray(adapter->FriendlyName) : QString();
        info.description = adapter->Description != nullptr ? QString::fromWCharArray(adapter->Description) : QString();
        out.insert(adapter->IfIndex, gpd::core::InterfaceClassifier::classify(info));
    }
    return out;
}

bool isVpnKind(const gpd::core::InterfaceKind kind) {
    return kind == gpd::core::InterfaceKind::VpnTunnel || kind == gpd::core::InterfaceKind::VirtualOverlay || kind == gpd::core::InterfaceKind::VirtualOther;
}

} // namespace

namespace gpd::platform {

QString VpnRouteProbe::probeId() const {
    return QStringLiteral("vpn_route");
}

bool VpnRouteProbe::start() {
    return true;
}

void VpnRouteProbe::stop() {
}

QVariantMap VpnRouteProbe::snapshot() const {
    QVariantMap out;
    const auto kinds = interfaceKindsByIndex();

    PMIB_IPFORWARD_TABLE2 table4 = nullptr;
    PMIB_IPFORWARD_TABLE2 table6 = nullptr;
    const bool has4 = GetIpForwardTable2(AF_INET, &table4) == NO_ERROR && table4 != nullptr;
    const bool has6 = GetIpForwardTable2(AF_INET6, &table6) == NO_ERROR && table6 != nullptr;

    bool full4 = false;
    bool full6 = false;
    QVariantMap route4;
    QVariantMap route6;

    if (has4) {
        ULONG bestMetric = 0xFFFFFFFFUL;
        for (ULONG i = 0; i < table4->NumEntries; ++i) {
            const auto& row = table4->Table[i];
            if (row.DestinationPrefix.Prefix.si_family != AF_INET || row.DestinationPrefix.PrefixLength != 0) {
                continue;
            }
            if (row.Metric >= bestMetric) {
                continue;
            }
            bestMetric = row.Metric;
            route4.insert(QStringLiteral("ifIndex"), static_cast<int>(row.InterfaceIndex));
            route4.insert(QStringLiteral("nextHop"), sockaddrToIp(row.NextHop));
            route4.insert(QStringLiteral("metric"), static_cast<int>(row.Metric));
            const auto kind = kinds.value(row.InterfaceIndex, gpd::core::InterfaceKind::Unknown);
            full4 = isVpnKind(kind);
        }
    }

    if (has6) {
        ULONG bestMetric = 0xFFFFFFFFUL;
        for (ULONG i = 0; i < table6->NumEntries; ++i) {
            const auto& row = table6->Table[i];
            if (row.DestinationPrefix.Prefix.si_family != AF_INET6 || row.DestinationPrefix.PrefixLength != 0) {
                continue;
            }
            if (row.Metric >= bestMetric) {
                continue;
            }
            bestMetric = row.Metric;
            route6.insert(QStringLiteral("ifIndex"), static_cast<int>(row.InterfaceIndex));
            route6.insert(QStringLiteral("nextHop"), sockaddrToIp(row.NextHop));
            route6.insert(QStringLiteral("metric"), static_cast<int>(row.Metric));
            const auto kind = kinds.value(row.InterfaceIndex, gpd::core::InterfaceKind::Unknown);
            full6 = isVpnKind(kind);
        }
    }

    out.insert(QStringLiteral("defaultIpv4"), route4);
    out.insert(QStringLiteral("defaultIpv6"), route6);
    out.insert(QStringLiteral("hasDefaultIpv4"), !route4.isEmpty());
    out.insert(QStringLiteral("hasDefaultIpv6"), !route6.isEmpty());
    out.insert(QStringLiteral("fullTunnelIpv4"), full4);
    out.insert(QStringLiteral("fullTunnelIpv6"), full6);
    out.insert(QStringLiteral("fullTunnelDetected"), full4 || full6);

    if (table4 != nullptr) {
        FreeMibTable(table4);
    }
    if (table6 != nullptr) {
        FreeMibTable(table6);
    }
    return out;
}

} // namespace gpd::platform
