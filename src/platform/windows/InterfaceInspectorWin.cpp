#include "platform/windows/InterfaceInspectorWin.h"

#include "core/InterfaceClassifier.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <iphlpapi.h>
#include <iptypes.h>

#include <array>
#include <vector>

namespace {

QString sockaddrToString(const SOCKADDR* address, const int addressLength) {
    if (address == nullptr || addressLength <= 0) {
        return QString();
    }

    wchar_t buffer[128]{};
    DWORD length = static_cast<DWORD>(std::size(buffer));
    if (WSAAddressToStringW(const_cast<LPSOCKADDR>(address), addressLength, nullptr, buffer, &length) != 0) {
        return QString();
    }
    return QString::fromWCharArray(buffer);
}

QString formatMac(const BYTE* bytes, const ULONG length) {
    if (bytes == nullptr || length == 0) {
        return QString();
    }

    QStringList parts;
    for (ULONG i = 0; i < length; ++i) {
        parts.push_back(QStringLiteral("%1").arg(bytes[i], 2, 16, QLatin1Char('0')).toUpper());
    }
    return parts.join(QLatin1Char(':'));
}

} // namespace

namespace gpd::platform {

QVector<gpd::core::NetworkInterfaceInfo> InterfaceInspectorWin::listInterfaces() const {
    QVector<gpd::core::NetworkInterfaceInfo> result;

    ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_ALL_INTERFACES;
    ULONG family = AF_UNSPEC;
    ULONG bufferSize = 0;
    ULONG attempts = 0;
    ULONG status = ERROR_BUFFER_OVERFLOW;
    std::vector<BYTE> buffer;

    while (attempts < 3 && status == ERROR_BUFFER_OVERFLOW) {
        ++attempts;
        status = GetAdaptersAddresses(family, flags, nullptr, nullptr, &bufferSize);
        if (status != ERROR_BUFFER_OVERFLOW) {
            break;
        }
        buffer.resize(bufferSize);
        auto* addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
        status = GetAdaptersAddresses(family, flags, nullptr, addresses, &bufferSize);
    }

    if (status != NO_ERROR || buffer.empty()) {
        return result;
    }

    auto* addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    for (auto* adapter = addresses; adapter != nullptr; adapter = adapter->Next) {
        gpd::core::NetworkInterfaceInfo info;
        info.ifIndex = adapter->IfIndex;
        info.luid = adapter->Luid.Value;
        info.friendlyName = adapter->FriendlyName != nullptr ? QString::fromWCharArray(adapter->FriendlyName) : QStringLiteral("-");
        info.description = adapter->Description != nullptr ? QString::fromWCharArray(adapter->Description) : QStringLiteral("-");
        info.ifType = adapter->IfType;
        info.tunnelType = adapter->TunnelType;
        info.operStatus = static_cast<std::uint32_t>(adapter->OperStatus);
        info.macAddress = formatMac(adapter->PhysicalAddress, adapter->PhysicalAddressLength);
        info.dnsSuffix = adapter->DnsSuffix != nullptr ? QString::fromWCharArray(adapter->DnsSuffix) : QString();

        for (auto* unicast = adapter->FirstUnicastAddress; unicast != nullptr; unicast = unicast->Next) {
            const auto ip = sockaddrToString(unicast->Address.lpSockaddr, unicast->Address.iSockaddrLength);
            if (!ip.isEmpty()) {
                info.unicastAddresses.push_back(ip);
            }
        }

        for (auto* gateway = adapter->FirstGatewayAddress; gateway != nullptr; gateway = gateway->Next) {
            const auto gw = sockaddrToString(gateway->Address.lpSockaddr, gateway->Address.iSockaddrLength);
            if (!gw.isEmpty()) {
                info.gatewayAddresses.push_back(gw);
            }
        }

        info.kind = gpd::core::InterfaceClassifier::classify(info);
        result.push_back(info);
    }

    return result;
}

} // namespace gpd::platform
