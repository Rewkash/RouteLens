#include "platform/windows/EtwParser.h"

#include <winsock2.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <ws2tcpip.h>

#include <QDateTime>

#include <array>
#include <vector>

namespace {

constexpr USHORT kUdpTask = 2;
constexpr USHORT kTcpTask = 1;
constexpr USHORT kKernelNetworkUdpTask = 2;
constexpr USHORT kKernelNetworkUdpTaskLegacy = 11;
constexpr USHORT kKernelNetworkTcpTask = 1;
constexpr USHORT kKernelNetworkTcpTaskLegacy = 10;
constexpr GUID kUdpIpGuid = {0xbf3a50c5, 0xa9c9, 0x4988, {0xa0, 0x05, 0x2d, 0xf0, 0xb7, 0xc8, 0x0f, 0x80}};
constexpr GUID kKernelNetworkGuid = {0x7DD42A49, 0x5329, 0x4832, {0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88}};

bool isSameGuid(const GUID& lhs, const GUID& rhs) noexcept {
    return memcmp(&lhs, &rhs, sizeof(GUID)) == 0;
}

std::optional<std::vector<BYTE>> getPropertyBlob(const PEVENT_RECORD record, const wchar_t* propertyName) {
    PROPERTY_DATA_DESCRIPTOR descriptor{};
    descriptor.PropertyName = reinterpret_cast<ULONGLONG>(propertyName);
    descriptor.ArrayIndex = ULONG_MAX;

    ULONG size = 0;
    auto status = TdhGetPropertySize(record, 0, nullptr, 1, &descriptor, &size);
    if (status != ERROR_SUCCESS || size == 0) {
        return std::nullopt;
    }

    std::vector<BYTE> data(size);
    status = TdhGetProperty(record, 0, nullptr, 1, &descriptor, size, data.data());
    if (status != ERROR_SUCCESS) {
        return std::nullopt;
    }

    return data;
}

template <typename T>
std::optional<T> getPropertyValue(const PEVENT_RECORD record, const wchar_t* propertyName) {
    const auto blob = getPropertyBlob(record, propertyName);
    if (!blob.has_value() || blob->size() < sizeof(T)) {
        return std::nullopt;
    }
    T value{};
    memcpy(&value, blob->data(), sizeof(T));
    return value;
}

QString parseIp(const std::vector<BYTE>& data) {
    wchar_t buffer[INET6_ADDRSTRLEN]{};
    if (data.size() == 4) {
        if (InetNtopW(AF_INET, data.data(), buffer, INET6_ADDRSTRLEN) == nullptr) {
            return QString();
        }
        return QString::fromWCharArray(buffer);
    }
    if (data.size() == 16) {
        if (InetNtopW(AF_INET6, data.data(), buffer, INET6_ADDRSTRLEN) == nullptr) {
            return QString();
        }
        return QString::fromWCharArray(buffer);
    }
    return QString();
}

} // namespace

namespace gpd::platform {

std::optional<gpd::core::UdpFlowEvent> EtwParser::parse(const void* recordPtr) const {
    if (recordPtr == nullptr) {
        return std::nullopt;
    }
    const auto record = static_cast<PEVENT_RECORD>(const_cast<void*>(recordPtr));
    const auto opcode = record->EventHeader.EventDescriptor.Opcode;
    const auto eventId = record->EventHeader.EventDescriptor.Id;
    const auto task = record->EventHeader.EventDescriptor.Task;
    const bool isClassicUdp = isSameGuid(record->EventHeader.ProviderId, kUdpIpGuid) || task == kUdpTask;
    const bool isClassicTcp = task == kTcpTask;
    const bool isKernelNetworkUdp = isSameGuid(record->EventHeader.ProviderId, kKernelNetworkGuid) &&
                                    (task == kKernelNetworkUdpTask || task == kKernelNetworkUdpTaskLegacy);
    const bool isKernelNetworkTcp = isSameGuid(record->EventHeader.ProviderId, kKernelNetworkGuid) &&
                                    (task == kKernelNetworkTcpTask || task == kKernelNetworkTcpTaskLegacy);
    if (!isClassicUdp && !isKernelNetworkUdp && !isClassicTcp && !isKernelNetworkTcp) {
        return std::nullopt;
    }
    if (!(opcode == 10 || opcode == 11 || opcode == 17 || opcode == 26 || opcode == 27 || opcode == 42 || opcode == 43 || eventId == 42 || eventId == 43 || eventId == 58 || eventId == 59)) {
        return std::nullopt;
    }

    auto pid = getPropertyValue<ULONG>(record, L"PID");
    auto sport = getPropertyValue<USHORT>(record, L"sport");
    auto dport = getPropertyValue<USHORT>(record, L"dport");
    auto sizeBytes = getPropertyValue<ULONG>(record, L"size");
    auto saddr = getPropertyBlob(record, L"saddr");
    auto daddr = getPropertyBlob(record, L"daddr");
    if (!pid.has_value() || !sport.has_value() || !dport.has_value() || !saddr.has_value() || !daddr.has_value()) {
        return std::nullopt;
    }

    gpd::core::UdpFlowEvent event;
    event.protocol = (isClassicTcp || isKernelNetworkTcp) ? gpd::core::TransportProtocol::Tcp : gpd::core::TransportProtocol::Udp;
    event.pid = static_cast<std::uint32_t>(*pid);
    event.isIPv6 = daddr->size() == 16;
    event.isSend = (opcode == 10 || opcode == 26 || opcode == 17 || opcode == 42 || eventId == 42 || eventId == 58);
    if (event.isSend) {
        event.localAddress = parseIp(*saddr);
        event.remoteAddress = parseIp(*daddr);
        event.localPort = ntohs(*sport);
        event.remotePort = ntohs(*dport);
    } else {
        event.localAddress = parseIp(*daddr);
        event.remoteAddress = parseIp(*saddr);
        event.localPort = ntohs(*dport);
        event.remotePort = ntohs(*sport);
    }
    event.timestampMs = QDateTime::currentMSecsSinceEpoch();
    event.sizeBytes = sizeBytes.value_or(0);
    if (event.localAddress.isEmpty() || event.remoteAddress.isEmpty()) {
        return std::nullopt;
    }
    return event;
}

} // namespace gpd::platform
