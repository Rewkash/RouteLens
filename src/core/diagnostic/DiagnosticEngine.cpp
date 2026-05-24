#include "core/diagnostic/DiagnosticEngine.h"

#include "core/PingScheduler.h"
#include "core/diagnostic/AnchorPingProbe.h"
#include "core/diagnostic/BackgroundTrafficProbe.h"
#include "core/diagnostic/BufferbloatProbe.h"
#include "core/UdpFlowAggregator.h"
#include "platform/windows/diagnostic/AdapterErrorProbe.h"
#include "platform/windows/diagnostic/CpuPressureProbe.h"
#include "platform/windows/diagnostic/HopProbe.h"
#include "platform/windows/diagnostic/PacketLossProbe.h"
#include "platform/windows/diagnostic/VpnRouteProbe.h"
#include "platform/windows/diagnostic/WifiMetricsProbe.h"

#include <QDateTime>
#include <QMutexLocker>
#include <QTimer>

namespace gpd::core {

DiagnosticEngine::DiagnosticEngine(PingScheduler* pingScheduler, QObject* parent)
    : QObject(parent)
    , anchorProbe_(std::make_unique<AnchorPingProbe>(pingScheduler))
    , bufferbloatProbe_(std::make_unique<BufferbloatProbe>(pingScheduler, this))
    , bgTrafficProbe_(std::make_unique<BackgroundTrafficProbe>(nullptr))
    , hopProbe_(std::make_unique<gpd::platform::HopProbe>(this))
    , lossProbe_(std::make_unique<gpd::platform::PacketLossProbe>(this))
    , adapterProbe_(std::make_unique<gpd::platform::AdapterErrorProbe>())
    , wifiProbe_(std::make_unique<gpd::platform::WifiMetricsProbe>())
    , cpuProbe_(std::make_unique<gpd::platform::CpuPressureProbe>())
    , vpnRouteProbe_(std::make_unique<gpd::platform::VpnRouteProbe>())
    , timer_(new QTimer(this)) {
    timer_->setInterval(5000);
    connect(timer_, &QTimer::timeout, this, &DiagnosticEngine::collectAndPublish);
    connect(bufferbloatProbe_.get(), &gpd::core::BufferbloatProbe::completed, this, [this](const QVariantMap& s) {
        snapshots_.insert(QStringLiteral("bufferbloat"), s);
        fullBufferDone_ = true;
        collectAndPublish();
        Q_EMIT fullDiagnosticProgress((fullHopDone_ && fullLossDone_) ? 100 : 80, QStringLiteral("Bufferbloat completed"));
        if (fullDiagnosticRunning_ && fullHopDone_ && fullBufferDone_ && fullLossDone_) {
            fullDiagnosticRunning_ = false;
            Q_EMIT fullDiagnosticCompleted(currentReport());
        }
    });
    connect(hopProbe_.get(), &gpd::platform::HopProbe::completed, this, [this](const QVariantMap& s) {
        snapshots_.insert(QStringLiteral("hop_probe"), s);
        fullHopDone_ = true;
        collectAndPublish();
        Q_EMIT fullDiagnosticProgress((fullBufferDone_ && fullLossDone_) ? 100 : 80, QStringLiteral("Hop trace completed"));
        if (fullDiagnosticRunning_ && fullHopDone_ && fullBufferDone_ && fullLossDone_) {
            fullDiagnosticRunning_ = false;
            Q_EMIT fullDiagnosticCompleted(currentReport());
        }
    });
    connect(lossProbe_.get(), &gpd::platform::PacketLossProbe::completed, this, [this](const QVariantMap& s) {
        snapshots_.insert(QStringLiteral("packet_loss"), s);
        fullLossDone_ = true;
        collectAndPublish();
        Q_EMIT fullDiagnosticProgress((fullHopDone_ && fullBufferDone_) ? 100 : 80, QStringLiteral("Packet loss probe completed"));
        if (fullDiagnosticRunning_ && fullHopDone_ && fullBufferDone_ && fullLossDone_) {
            fullDiagnosticRunning_ = false;
            Q_EMIT fullDiagnosticCompleted(currentReport());
        }
    });
}

DiagnosticEngine::~DiagnosticEngine() = default;

void DiagnosticEngine::setTarget(const QString& ip, const int port, const QString& processName, const QString& localAddress) {
    targetIp_ = ip;
    targetPort_ = port;
    processName_ = processName;
    targetLocalAddress_ = localAddress;
    snapshots_.clear();
    anchorProbe_->setTarget(ip, port, localAddress);
    bufferbloatProbe_->setTarget(ip, localAddress);
    hopProbe_->setTarget(ip);
    lossProbe_->setTarget(ip, localAddress);
}

void DiagnosticEngine::setConnectionContext(const ConnectionInfo& connectionInfo) {
    contextConnection_ = connectionInfo;
}

void DiagnosticEngine::setTargetPid(const std::uint32_t pid) {
    if (bgTrafficProbe_ != nullptr) {
        bgTrafficProbe_->setTargetPid(pid);
    }
}

void DiagnosticEngine::setUdpFlowAggregator(const UdpFlowAggregator* udpFlows) {
    bgTrafficProbe_ = std::make_unique<BackgroundTrafficProbe>(udpFlows);
}

void DiagnosticEngine::clearConnectionContext() {
    contextConnection_.reset();
}

void DiagnosticEngine::startContinuous(const int probeIntervalMs) {
    timer_->setInterval(qMax(1000, probeIntervalMs));
    anchorProbe_->start();
    adapterProbe_->start();
    wifiProbe_->start();
    cpuProbe_->start();
    bgTrafficProbe_->start();
    vpnRouteProbe_->start();
    timer_->start();
    collectAndPublish();
}

void DiagnosticEngine::runFullDiagnostic() {
    fullDiagnosticRunning_ = true;
    fullHopDone_ = false;
    fullBufferDone_ = false;
    fullLossDone_ = false;
    Q_EMIT fullDiagnosticProgress(10, QStringLiteral("Collecting baseline probes"));
    collectAndPublish();
    Q_EMIT fullDiagnosticProgress(30, QStringLiteral("Running hop trace"));
    hopProbe_->runTest();
    Q_EMIT fullDiagnosticProgress(50, QStringLiteral("Running packet loss probe"));
    lossProbe_->runTest();
    Q_EMIT fullDiagnosticProgress(60, QStringLiteral("Running load test"));
    bufferbloatProbe_->runTest(10000);
}

void DiagnosticEngine::stop() {
    timer_->stop();
    anchorProbe_->stop();
    adapterProbe_->stop();
    wifiProbe_->stop();
    cpuProbe_->stop();
    bgTrafficProbe_->stop();
    vpnRouteProbe_->stop();
    bufferbloatProbe_->stop();
    hopProbe_->stop();
    lossProbe_->stop();
}

DiagnosticReport DiagnosticEngine::currentReport() const {
    QMutexLocker lock(&reportMutex_);
    return report_;
}

void DiagnosticEngine::collectAndPublish() {
    snapshots_.insert(anchorProbe_->probeId(), anchorProbe_->snapshot());
    snapshots_.insert(adapterProbe_->probeId(), adapterProbe_->snapshot());
    snapshots_.insert(wifiProbe_->probeId(), wifiProbe_->snapshot());
    snapshots_.insert(cpuProbe_->probeId(), cpuProbe_->snapshot());
    snapshots_.insert(bgTrafficProbe_->probeId(), bgTrafficProbe_->snapshot());
    snapshots_.insert(vpnRouteProbe_->probeId(), vpnRouteProbe_->snapshot());

    const auto report = ruleEngine_.buildReport(targetIp_,
                                                targetPort_,
                                                processName_,
                                                snapshots_,
                                                contextConnection_.has_value() ? &contextConnection_.value() : nullptr);
    {
        QMutexLocker lock(&reportMutex_);
        report_ = report;
        if (report_.startedAtMs == 0) {
            report_.startedAtMs = QDateTime::currentMSecsSinceEpoch();
        }
        report_.completedAtMs = QDateTime::currentMSecsSinceEpoch();
    }
    Q_EMIT reportUpdated(report);
}

} // namespace gpd::core
