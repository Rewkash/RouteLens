#include "platform/windows/ConnectionScannerWin.h"

#include <qt_windows.h>

#include <iphlpapi.h>
#include <iptypes.h>
#include <ws2tcpip.h>

#ifndef MIB_TCP_STATE_DELETE_TCB
#define MIB_TCP_STATE_DELETE_TCB 12
#endif

#include <algorithm>
#include <vector>

namespace {

QString sockaddrToString(const SOCKADDR* addr, const socklen_t addrLen) {
    wchar_t buffer[INET6_ADDRSTRLEN]{};
    DWORD bufferSize = static_cast<DWORD>(std::size(buffer));
    if (WSAAddressToStringW(const_cast<LPSOCKADDR>(addr), addrLen, nullptr, buffer, &bufferSize) == 0) {
        return QString::fromWCharArray(buffer);
    }
    return QStringLiteral("-");
}

QString ip4ToString(const DWORD ipAddr) {
    IN_ADDR addr{};
    addr.S_un.S_addr = ipAddr;
    SOCKADDR_IN socketAddr{};
    socketAddr.sin_family = AF_INET;
    socketAddr.sin_addr = addr;
    return sockaddrToString(reinterpret_cast<const SOCKADDR*>(&socketAddr), sizeof(socketAddr));
}

QString ip6ToString(const UCHAR ipAddr[16]) {
    SOCKADDR_IN6 socketAddr{};
    socketAddr.sin6_family = AF_INET6;
    memcpy(&socketAddr.sin6_addr, ipAddr, 16);
    return sockaddrToString(reinterpret_cast<const SOCKADDR*>(&socketAddr), sizeof(socketAddr));
}

std::uint16_t networkPortToHost(const DWORD netPort) {
    return ntohs(static_cast<u_short>(netPort));
}

} // namespace

namespace gpd::platform {

struct Tcp6RowOwnerPidLocal {
    UCHAR ucLocalAddr[16];
    DWORD dwLocalScopeId;
    DWORD dwLocalPort;
    UCHAR ucRemoteAddr[16];
    DWORD dwRemoteScopeId;
    DWORD dwRemotePort;
    DWORD dwState;
    DWORD dwOwningPid;
};

struct Tcp6TableOwnerPidLocal {
    DWORD dwNumEntries;
    Tcp6RowOwnerPidLocal table[1];
};

struct Udp6RowOwnerPidLocal {
    UCHAR ucLocalAddr[16];
    DWORD dwLocalScopeId;
    DWORD dwLocalPort;
    DWORD dwOwningPid;
};

struct Udp6TableOwnerPidLocal {
    DWORD dwNumEntries;
    Udp6RowOwnerPidLocal table[1];
};

template <typename TableType, typename QueryFn>
bool loadOwnerTable(std::vector<unsigned char>& buffer, QueryFn&& query) {
    DWORD size = 0;
    DWORD status = query(nullptr, &size);
    if (status != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        return false;
    }

    for (int attempt = 0; attempt < 3; ++attempt) {
        buffer.resize(size);
        auto* table = reinterpret_cast<TableType*>(buffer.data());
        status = query(table, &size);
        if (status == NO_ERROR) {
            return true;
        }
        if (status != ERROR_INSUFFICIENT_BUFFER) {
            return false;
        }
    }

    return false;
}

QHash<std::uint32_t, int> ConnectionScannerWin::activePidConnectionCounts() const {
    QHash<std::uint32_t, int> counts;

    auto countTcp4 = [&](std::vector<unsigned char>& buffer) {
        const auto ok = loadOwnerTable<MIB_TCPTABLE_OWNER_PID>(buffer, [](MIB_TCPTABLE_OWNER_PID* table, DWORD* size) {
            return GetExtendedTcpTable(table, size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        });
        if (!ok) {
            return;
        }
        auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
        for (DWORD index = 0; index < table->dwNumEntries; ++index) {
            const auto pid = static_cast<std::uint32_t>(table->table[index].dwOwningPid);
            counts[pid] = counts.value(pid) + 1;
        }
    };

    auto countUdp4 = [&](std::vector<unsigned char>& buffer) {
        const auto ok = loadOwnerTable<MIB_UDPTABLE_OWNER_PID>(buffer, [](MIB_UDPTABLE_OWNER_PID* table, DWORD* size) {
            return GetExtendedUdpTable(table, size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        });
        if (!ok) {
            return;
        }
        auto* table = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(buffer.data());
        for (DWORD index = 0; index < table->dwNumEntries; ++index) {
            const auto pid = static_cast<std::uint32_t>(table->table[index].dwOwningPid);
            counts[pid] = counts.value(pid) + 1;
        }
    };

    auto countTcp6 = [&](std::vector<unsigned char>& buffer) {
        const auto ok = loadOwnerTable<Tcp6TableOwnerPidLocal>(buffer, [](Tcp6TableOwnerPidLocal* table, DWORD* size) {
            return GetExtendedTcpTable(table, size, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        });
        if (!ok) {
            return;
        }
        auto* table = reinterpret_cast<Tcp6TableOwnerPidLocal*>(buffer.data());
        for (DWORD index = 0; index < table->dwNumEntries; ++index) {
            const auto pid = static_cast<std::uint32_t>(table->table[index].dwOwningPid);
            counts[pid] = counts.value(pid) + 1;
        }
    };

    auto countUdp6 = [&](std::vector<unsigned char>& buffer) {
        const auto ok = loadOwnerTable<Udp6TableOwnerPidLocal>(buffer, [](Udp6TableOwnerPidLocal* table, DWORD* size) {
            return GetExtendedUdpTable(table, size, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
        });
        if (!ok) {
            return;
        }
        auto* table = reinterpret_cast<Udp6TableOwnerPidLocal*>(buffer.data());
        for (DWORD index = 0; index < table->dwNumEntries; ++index) {
            const auto pid = static_cast<std::uint32_t>(table->table[index].dwOwningPid);
            counts[pid] = counts.value(pid) + 1;
        }
    };

    auto loadTable = [&](auto callback, const int initialSize) {
        std::vector<unsigned char> buffer(static_cast<size_t>(initialSize));
        callback(buffer);
    };

    loadTable(countTcp4, 256 * 1024);
    loadTable(countTcp6, 256 * 1024);
    loadTable(countUdp4, 256 * 1024);
    loadTable(countUdp6, 256 * 1024);

    return counts;
}

QVector<gpd::core::ConnectionInfo> ConnectionScannerWin::listConnectionsForPid(const std::uint32_t pid) const {
    QVector<gpd::core::ConnectionInfo> result;

    auto appendTcp4 = [&](std::vector<unsigned char>& buffer) {
        const auto ok = loadOwnerTable<MIB_TCPTABLE_OWNER_PID>(buffer, [](MIB_TCPTABLE_OWNER_PID* table, DWORD* size) {
            return GetExtendedTcpTable(table, size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        });
        if (!ok) {
            return;
        }
        auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
        for (DWORD index = 0; index < table->dwNumEntries; ++index) {
            const auto& row = table->table[index];
            if (row.dwOwningPid != pid) {
                continue;
            }
            gpd::core::ConnectionInfo item;
            item.pid = pid;
            item.protocol = gpd::core::TransportProtocol::Tcp;
            item.localAddress = ip4ToString(row.dwLocalAddr);
            item.localPort = networkPortToHost(row.dwLocalPort);
            item.remoteAddress = ip4ToString(row.dwRemoteAddr);
            item.remotePort = networkPortToHost(row.dwRemotePort);
            result.push_back(item);
        }
    };


    auto appendUdp4 = [&](std::vector<unsigned char>& buffer) {
        const auto ok = loadOwnerTable<MIB_UDPTABLE_OWNER_PID>(buffer, [](MIB_UDPTABLE_OWNER_PID* table, DWORD* size) {
            return GetExtendedUdpTable(table, size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        });
        if (!ok) {
            return;
        }
        auto* table = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(buffer.data());
        for (DWORD index = 0; index < table->dwNumEntries; ++index) {
            const auto& row = table->table[index];
            if (row.dwOwningPid != pid) {
                continue;
            }
            gpd::core::ConnectionInfo item;
            item.pid = pid;
            item.protocol = gpd::core::TransportProtocol::Udp;
            item.localAddress = ip4ToString(row.dwLocalAddr);
            item.localPort = networkPortToHost(row.dwLocalPort);
            item.remoteAddress = QStringLiteral("-");
            item.remotePort = 0;
            result.push_back(item);
        }
    };

    auto appendTcp6 = [&](std::vector<unsigned char>& buffer) {
        const auto ok = loadOwnerTable<Tcp6TableOwnerPidLocal>(buffer, [](Tcp6TableOwnerPidLocal* table, DWORD* size) {
            return GetExtendedTcpTable(table, size, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        });
        if (!ok) {
            return;
        }
        auto* table = reinterpret_cast<Tcp6TableOwnerPidLocal*>(buffer.data());
        for (DWORD index = 0; index < table->dwNumEntries; ++index) {
            const auto& row = table->table[index];
            if (row.dwOwningPid != pid) {
                continue;
            }
            gpd::core::ConnectionInfo item;
            item.pid = pid;
            item.protocol = gpd::core::TransportProtocol::Tcp;
            item.localAddress = ip6ToString(row.ucLocalAddr);
            item.localPort = networkPortToHost(row.dwLocalPort);
            item.remoteAddress = ip6ToString(row.ucRemoteAddr);
            item.remotePort = networkPortToHost(row.dwRemotePort);
            result.push_back(item);
        }
    };

    auto appendUdp6 = [&](std::vector<unsigned char>& buffer) {
        const auto ok = loadOwnerTable<Udp6TableOwnerPidLocal>(buffer, [](Udp6TableOwnerPidLocal* table, DWORD* size) {
            return GetExtendedUdpTable(table, size, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
        });
        if (!ok) {
            return;
        }
        auto* table = reinterpret_cast<Udp6TableOwnerPidLocal*>(buffer.data());
        for (DWORD index = 0; index < table->dwNumEntries; ++index) {
            const auto& row = table->table[index];
            if (row.dwOwningPid != pid) {
                continue;
            }
            gpd::core::ConnectionInfo item;
            item.pid = pid;
            item.protocol = gpd::core::TransportProtocol::Udp;
            item.localAddress = ip6ToString(row.ucLocalAddr);
            item.localPort = networkPortToHost(row.dwLocalPort);
            item.remoteAddress = QStringLiteral("-");
            item.remotePort = 0;
            result.push_back(item);
        }
    };


    auto loadTable = [&](auto callback, const int initialSize) {
        std::vector<unsigned char> buffer(static_cast<size_t>(initialSize));
        callback(buffer);
    };

    loadTable(appendTcp4, 256 * 1024);
    loadTable(appendTcp6, 256 * 1024);
    loadTable(appendUdp4, 256 * 1024);
    loadTable(appendUdp6, 256 * 1024);

    std::sort(result.begin(), result.end(), [](const gpd::core::ConnectionInfo& lhs, const gpd::core::ConnectionInfo& rhs) {
        if (lhs.protocol != rhs.protocol) {
            return lhs.protocol == gpd::core::TransportProtocol::Tcp;
        }
        if (lhs.remoteAddress != rhs.remoteAddress) {
            return lhs.remoteAddress < rhs.remoteAddress;
        }
        if (lhs.remotePort != rhs.remotePort) {
            return lhs.remotePort < rhs.remotePort;
        }
        if (lhs.localAddress != rhs.localAddress) {
            return lhs.localAddress < rhs.localAddress;
        }
        return lhs.localPort < rhs.localPort;
    });

    return result;
}

} // namespace gpd::platform
