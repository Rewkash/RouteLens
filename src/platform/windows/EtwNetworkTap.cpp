#include "platform/windows/EtwNetworkTap.h"

#include "platform/windows/EtwParser.h"

#include <winsock2.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include <QMetaObject>

#include <array>
#include <vector>

namespace {

constexpr wchar_t kSessionName[] = L"RouteLens-KernelNet";
constexpr GUID kKernelNetworkProviderGuid = {0x7DD42A49, 0x5329, 0x4832, {0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88}};

struct SessionContext {
    gpd::platform::EtwNetworkTap* owner{nullptr};
    gpd::platform::EtwParser parser;
    std::vector<gpd::core::UdpFlowEvent> batch;
    std::mutex batchMutex;
};

void flushBatch(SessionContext* context) {
    QVector<gpd::core::UdpFlowEvent> out;
    {
        std::lock_guard<std::mutex> lock(context->batchMutex);
        if (context->batch.empty()) {
            return;
        }
        out.reserve(static_cast<int>(context->batch.size()));
        for (const auto& event : context->batch) {
            out.push_back(event);
        }
        context->batch.clear();
    }
    QMetaObject::invokeMethod(context->owner, [owner = context->owner, out]() { owner->dispatchUdpBatch(out); }, Qt::QueuedConnection);
}

VOID WINAPI eventRecordCallback(PEVENT_RECORD record) {
    auto* context = static_cast<SessionContext*>(record->UserContext);
    if (context == nullptr) {
        return;
    }

    try {
        auto parsed = context->parser.parse(record);
        if (!parsed.has_value()) {
            return;
        }

        bool shouldFlush = false;
        {
            std::lock_guard<std::mutex> lock(context->batchMutex);
            context->batch.push_back(*parsed);
            shouldFlush = context->batch.size() >= 256;
        }
        if (shouldFlush) {
            flushBatch(context);
        }
    } catch (...) {
    }
}

} // namespace

namespace gpd::platform {

EtwNetworkTap::EtwNetworkTap(QObject* parent)
    : QObject(parent) {
    qRegisterMetaType<gpd::platform::EtwStatus>("gpd::platform::EtwStatus");
}

EtwNetworkTap::~EtwNetworkTap() {
    stop();
}

bool EtwNetworkTap::start() {
    if (status() == EtwStatus::Running || status() == EtwStatus::Starting) {
        return true;
    }

    stopRequested_.store(false);
    setStatus(EtwStatus::Starting);

    worker_ = std::thread([this]() {
        runTraceLoop();
    });
    return true;
}

void EtwNetworkTap::stop() {
    stopRequested_.store(true);

    std::array<BYTE, sizeof(EVENT_TRACE_PROPERTIES) + 2 * 1024> propsBuffer{};
    auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propsBuffer.data());
    props->Wnode.BufferSize = static_cast<ULONG>(propsBuffer.size());
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    ControlTraceW(0, kSessionName, props, EVENT_TRACE_CONTROL_STOP);

    if (worker_.joinable()) {
        worker_.join();
    }

    setStatus(EtwStatus::Stopped);
}

EtwStatus EtwNetworkTap::status() const noexcept {
    return status_.load();
}

EtwStartError EtwNetworkTap::lastError() const noexcept {
    std::lock_guard<std::mutex> lock(stateMutex_);
    return lastError_;
}

void EtwNetworkTap::dispatchUdpBatch(QVector<gpd::core::UdpFlowEvent> events) {
    Q_EMIT udpEventBatch(events);
}

void EtwNetworkTap::setStatus(const EtwStatus statusValue) {
    status_.store(statusValue);
    Q_EMIT statusChanged(statusValue);
}

void EtwNetworkTap::runTraceLoop() {
    std::array<BYTE, sizeof(EVENT_TRACE_PROPERTIES) + 2 * 1024> propsBuffer{};
    auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propsBuffer.data());
    props->Wnode.BufferSize = static_cast<ULONG>(propsBuffer.size());
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ControlTraceW(0, kSessionName, props, EVENT_TRACE_CONTROL_STOP);

    TRACEHANDLE sessionHandle = 0;
    auto statusCode = StartTraceW(&sessionHandle, kSessionName, props);
    if (statusCode == ERROR_ALREADY_EXISTS) {
        ControlTraceW(0, kSessionName, props, EVENT_TRACE_CONTROL_STOP);
        statusCode = StartTraceW(&sessionHandle, kSessionName, props);
    }
    if (statusCode != ERROR_SUCCESS) {
        {
            std::lock_guard<std::mutex> lock(stateMutex_);
            lastError_.lastError = statusCode;
            lastError_.message = QStringLiteral("StartTraceW failed: %1").arg(statusCode);
        }
        setStatus(EtwStatus::Failed);
        return;
    }

    statusCode = EnableTraceEx2(sessionHandle,
                                &kKernelNetworkProviderGuid,
                                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                TRACE_LEVEL_INFORMATION,
                                0x30ULL,
                                0,
                                0,
                                nullptr);
    if (statusCode != ERROR_SUCCESS) {
        ControlTraceW(sessionHandle, kSessionName, props, EVENT_TRACE_CONTROL_STOP);
        {
            std::lock_guard<std::mutex> lock(stateMutex_);
            lastError_.lastError = statusCode;
            lastError_.message = QStringLiteral("EnableTraceEx2(system network) failed: %1").arg(statusCode);
        }
        setStatus(EtwStatus::Failed);
        return;
    }

    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName = const_cast<LPWSTR>(kSessionName);
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
    logfile.EventRecordCallback = eventRecordCallback;

    SessionContext context;
    context.owner = this;
    logfile.Context = &context;

    TRACEHANDLE consumerHandle = OpenTraceW(&logfile);
    if (consumerHandle == INVALID_PROCESSTRACE_HANDLE) {
        ControlTraceW(sessionHandle, kSessionName, props, EVENT_TRACE_CONTROL_STOP);
        {
            std::lock_guard<std::mutex> lock(stateMutex_);
            lastError_.lastError = GetLastError();
            lastError_.message = QStringLiteral("OpenTraceW failed: %1").arg(lastError_.lastError);
        }
        setStatus(EtwStatus::Failed);
        return;
    }

    setStatus(EtwStatus::Running);
    ProcessTrace(&consumerHandle, 1, nullptr, nullptr);
    flushBatch(&context);
    CloseTrace(consumerHandle);
    ControlTraceW(sessionHandle, kSessionName, props, EVENT_TRACE_CONTROL_STOP);

    if (!stopRequested_.load()) {
        setStatus(EtwStatus::Failed);
    }
}

} // namespace gpd::platform
