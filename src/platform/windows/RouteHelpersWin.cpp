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

} // namespace gpd::platform
