#include "platform/windows/diagnostic/WifiMetricsProbe.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wlanapi.h>

namespace gpd::platform {

QString WifiMetricsProbe::probeId() const {
    return QStringLiteral("wifi_metrics");
}

bool WifiMetricsProbe::start() {
    return true;
}

void WifiMetricsProbe::stop() {
}

QVariantMap WifiMetricsProbe::snapshot() const {
    QVariantMap out;
    DWORD clientVersion = 2;
    DWORD negotiated = 0;
    HANDLE handle = nullptr;
    if (WlanOpenHandle(clientVersion, nullptr, &negotiated, &handle) != ERROR_SUCCESS || handle == nullptr) {
        return out;
    }

    PWLAN_INTERFACE_INFO_LIST interfaces = nullptr;
    if (WlanEnumInterfaces(handle, nullptr, &interfaces) != ERROR_SUCCESS || interfaces == nullptr) {
        WlanCloseHandle(handle, nullptr);
        return out;
    }

    for (unsigned i = 0; i < interfaces->dwNumberOfItems; ++i) {
        const auto& iface = interfaces->InterfaceInfo[i];
        if (iface.isState != wlan_interface_state_connected) {
            continue;
        }
        PWLAN_CONNECTION_ATTRIBUTES attrs = nullptr;
        DWORD size = 0;
        WLAN_OPCODE_VALUE_TYPE opCode = wlan_opcode_value_type_invalid;
        if (WlanQueryInterface(handle,
                               &iface.InterfaceGuid,
                               wlan_intf_opcode_current_connection,
                               nullptr,
                               &size,
                               reinterpret_cast<PVOID*>(&attrs),
                               &opCode) != ERROR_SUCCESS ||
            attrs == nullptr) {
            continue;
        }

        const int quality = static_cast<int>(attrs->wlanAssociationAttributes.wlanSignalQuality);
        const int rssiDbm = (quality / 2) - 100;
        const int rxMbps = static_cast<int>(attrs->wlanAssociationAttributes.ulRxRate / 1000);
        const int txMbps = static_cast<int>(attrs->wlanAssociationAttributes.ulTxRate / 1000);
        const int linkMbps = qMin(rxMbps, txMbps);

        out.insert(QStringLiteral("ssid"), QString::fromLatin1(reinterpret_cast<const char*>(attrs->wlanAssociationAttributes.dot11Ssid.ucSSID),
                                                                 static_cast<int>(attrs->wlanAssociationAttributes.dot11Ssid.uSSIDLength)));
        out.insert(QStringLiteral("signalQuality"), quality);
        out.insert(QStringLiteral("rssidBm"), rssiDbm);
        out.insert(QStringLiteral("linkSpeedMbps"), linkMbps);

        ULONG* channel = nullptr;
        DWORD chSize = 0;
        if (WlanQueryInterface(handle,
                               &iface.InterfaceGuid,
                               wlan_intf_opcode_channel_number,
                               nullptr,
                               &chSize,
                               reinterpret_cast<PVOID*>(&channel),
                               &opCode) == ERROR_SUCCESS &&
            channel != nullptr) {
            out.insert(QStringLiteral("channel"), static_cast<int>(*channel));
            WlanFreeMemory(channel);
        }

        WlanFreeMemory(attrs);
        break;
    }

    WlanFreeMemory(interfaces);
    WlanCloseHandle(handle, nullptr);
    return out;
}

} // namespace gpd::platform
