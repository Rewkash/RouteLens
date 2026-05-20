#include "platform/windows/RouteResolverWin.h"

#include <qt_windows.h>

#include <iphlpapi.h>
#include <ws2tcpip.h>

namespace gpd::platform {

std::optional<gpd::core::RoutingDecision> RouteResolverWin::resolveRouteFor(const QString& remoteIp) const {
    SOCKADDR_STORAGE storage{};
    int sockaddrLen = 0;

    SOCKADDR_IN addr4{};
    addr4.sin_family = AF_INET;
    if (InetPtonW(AF_INET, reinterpret_cast<LPCWSTR>(remoteIp.utf16()), &addr4.sin_addr) == 1) {
        memcpy(&storage, &addr4, sizeof(addr4));
        sockaddrLen = sizeof(addr4);
    } else {
        SOCKADDR_IN6 addr6{};
        addr6.sin6_family = AF_INET6;
        if (InetPtonW(AF_INET6, reinterpret_cast<LPCWSTR>(remoteIp.utf16()), &addr6.sin6_addr) != 1) {
            return std::nullopt;
        }
        memcpy(&storage, &addr6, sizeof(addr6));
        sockaddrLen = sizeof(addr6);
    }

    DWORD bestIfIndex = 0;
    const auto status = GetBestInterfaceEx(reinterpret_cast<sockaddr*>(&storage), &bestIfIndex);
    if (status != NO_ERROR || bestIfIndex == 0) {
        return std::nullopt;
    }

    gpd::core::RoutingDecision decision;
    decision.ifIndex = bestIfIndex;
    return decision;
}

} // namespace gpd::platform
