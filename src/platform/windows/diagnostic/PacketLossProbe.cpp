#include "platform/windows/diagnostic/PacketLossProbe.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <iphlpapi.h>

#include <QProcess>
#include <QRegularExpression>

#include <vector>

namespace {

QString sockaddrToIp(const SOCKADDR* address) {
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

double parseLossPercent(const QString& output) {
    const QRegularExpression rx(QStringLiteral("(\\d+)\\%\\s*loss"), QRegularExpression::CaseInsensitiveOption);
    const auto m = rx.match(output);
    if (m.hasMatch()) {
        return m.captured(1).toDouble();
    }
    const QRegularExpression rxRu(QStringLiteral("(\\d+)\\%\\s*пот"), QRegularExpression::CaseInsensitiveOption);
    const auto mr = rxRu.match(output);
    if (mr.hasMatch()) {
        return mr.captured(1).toDouble();
    }
    return -1.0;
}

double parseAvgRtt(const QString& output) {
    const QRegularExpression rx(QStringLiteral("Average\\s*=\\s*(\\d+)ms"), QRegularExpression::CaseInsensitiveOption);
    const auto m = rx.match(output);
    if (m.hasMatch()) {
        return m.captured(1).toDouble();
    }
    const QRegularExpression rxRu(QStringLiteral("Среднее\\s*=\\s*(\\d+)\\s*мс"), QRegularExpression::CaseInsensitiveOption);
    const auto mr = rxRu.match(output);
    if (mr.hasMatch()) {
        return mr.captured(1).toDouble();
    }
    return -1.0;
}

} // namespace

namespace gpd::platform {

PacketLossProbe::PacketLossProbe(QObject* parent)
    : QObject(parent)
    , process_(new QProcess(this)) {
    connect(process_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this, [this](int, QProcess::ExitStatus) {
        const QString output = QString::fromLocal8Bit(process_->readAllStandardOutput());
        parseAndStore(currentKey_, output);
        runNext();
    });
}

void PacketLossProbe::setTarget(const QString& targetIp, const QString& localAddress) {
    targetIp_ = targetIp;
    localAddress_ = localAddress;
    gatewayIp_ = detectGatewayForLocalAddress(localAddress);
}

void PacketLossProbe::runTest() {
    if (process_->state() != QProcess::NotRunning || targetIp_.isEmpty()) {
        return;
    }
    queue_.clear();
    queue_.push_back(QStringLiteral("target"));
    if (!gatewayIp_.isEmpty()) {
        queue_.push_back(QStringLiteral("first_hop"));
    }
    runNext();
}

QString PacketLossProbe::probeId() const {
    return QStringLiteral("packet_loss");
}

bool PacketLossProbe::start() {
    return true;
}

void PacketLossProbe::stop() {
    queue_.clear();
    if (process_->state() != QProcess::NotRunning) {
        process_->kill();
    }
}

QVariantMap PacketLossProbe::snapshot() const {
    return lastSnapshot_;
}

void PacketLossProbe::runNext() {
    if (queue_.isEmpty()) {
        Q_EMIT completed(lastSnapshot_);
        return;
    }
    currentKey_ = queue_.takeFirst();
    const QString ip = currentKey_ == QStringLiteral("first_hop") ? gatewayIp_ : targetIp_;
    if (ip.isEmpty()) {
        runNext();
        return;
    }
    process_->start(QStringLiteral("ping"), {QStringLiteral("-n"), QStringLiteral("20"), QStringLiteral("-w"), QStringLiteral("500"), ip});
}

void PacketLossProbe::parseAndStore(const QString& key, const QString& output) {
    QVariantMap m;
    m.insert(QStringLiteral("lossPercent"), parseLossPercent(output));
    m.insert(QStringLiteral("avgRttMs"), parseAvgRtt(output));
    m.insert(QStringLiteral("packetsSent"), 20);
    m.insert(QStringLiteral("available"), true);
    if (key == QStringLiteral("first_hop")) {
        m.insert(QStringLiteral("ip"), gatewayIp_);
    } else {
        m.insert(QStringLiteral("ip"), targetIp_);
    }
    lastSnapshot_.insert(key, m);
}

QString PacketLossProbe::detectGatewayForLocalAddress(const QString& localAddress) const {
    if (localAddress.isEmpty()) {
        return {};
    }

    ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_ALL_INTERFACES;
    ULONG family = AF_UNSPEC;
    ULONG bufferSize = 0;
    ULONG status = GetAdaptersAddresses(family, flags, nullptr, nullptr, &bufferSize);
    if (status != ERROR_BUFFER_OVERFLOW || bufferSize == 0) {
        return {};
    }

    std::vector<BYTE> buffer(bufferSize);
    auto* addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    status = GetAdaptersAddresses(family, flags, nullptr, addresses, &bufferSize);
    if (status != NO_ERROR) {
        return {};
    }

    for (auto* adapter = addresses; adapter != nullptr; adapter = adapter->Next) {
        bool localMatch = false;
        for (auto* unicast = adapter->FirstUnicastAddress; unicast != nullptr; unicast = unicast->Next) {
            if (sockaddrToIp(unicast->Address.lpSockaddr) == localAddress) {
                localMatch = true;
                break;
            }
        }
        if (!localMatch) {
            continue;
        }
        for (auto* gateway = adapter->FirstGatewayAddress; gateway != nullptr; gateway = gateway->Next) {
            const QString gw = sockaddrToIp(gateway->Address.lpSockaddr);
            if (!gw.isEmpty() && !gw.contains(QLatin1Char(':'))) {
                return gw;
            }
        }
    }
    return {};
}

} // namespace gpd::platform
