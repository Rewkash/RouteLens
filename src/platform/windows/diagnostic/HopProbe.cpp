#include "platform/windows/diagnostic/HopProbe.h"

#include <QProcess>
#include <QRegularExpression>

namespace gpd::platform {

HopProbe::HopProbe(QObject* parent)
    : QObject(parent)
    , process_(new QProcess(this)) {
    connect(process_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this, [this](int, QProcess::ExitStatus) {
        const QString output = QString::fromLocal8Bit(process_->readAllStandardOutput());
        parseOutput(output);
        Q_EMIT completed(lastSnapshot_);
    });
}

void HopProbe::setTarget(const QString& ip) {
    targetIp_ = ip;
}

void HopProbe::runTest() {
    if (targetIp_.isEmpty() || process_->state() != QProcess::NotRunning) {
        return;
    }
    process_->start(QStringLiteral("tracert"), {QStringLiteral("-d"), QStringLiteral("-h"), QStringLiteral("30"), QStringLiteral("-w"), QStringLiteral("800"), targetIp_});
}

QString HopProbe::probeId() const {
    return QStringLiteral("hop_probe");
}

bool HopProbe::start() {
    return true;
}

void HopProbe::stop() {
    if (process_->state() != QProcess::NotRunning) {
        process_->kill();
    }
}

QVariantMap HopProbe::snapshot() const {
    return lastSnapshot_;
}

void HopProbe::parseOutput(const QString& output) {
    QVariantList hops;
    const auto lines = output.split(QChar('\n'));
    const QRegularExpression hopRx(QStringLiteral("^\\s*(\\d+)\\s+(.+)$"));
    const QRegularExpression ipRx(QStringLiteral("(\\d+\\.\\d+\\.\\d+\\.\\d+)$"));

    int completedHops = 0;
    bool reached = false;

    for (const auto& raw : lines) {
        const QString line = raw.trimmed();
        const auto hm = hopRx.match(line);
        if (!hm.hasMatch()) {
            continue;
        }
        const int index = hm.captured(1).toInt();
        const QString tail = hm.captured(2);

        QVariantMap hop;
        hop.insert(QStringLiteral("index"), index);
        if (tail.contains(QStringLiteral("*"))) {
            hop.insert(QStringLiteral("ip"), QStringLiteral("*"));
            hop.insert(QStringLiteral("lossPercent"), 100.0);
        } else {
            const auto ipm = ipRx.match(tail);
            const QString ip = ipm.hasMatch() ? ipm.captured(1) : QStringLiteral("*");
            hop.insert(QStringLiteral("ip"), ip);
            hop.insert(QStringLiteral("lossPercent"), 0.0);
            QRegularExpression msRx(QStringLiteral("(\\d+)\\s*ms"));
            auto it = msRx.globalMatch(tail);
            int sum = 0;
            int cnt = 0;
            while (it.hasNext()) {
                const auto m = it.next();
                sum += m.captured(1).toInt();
                ++cnt;
            }
            hop.insert(QStringLiteral("rttAvgMs"), cnt > 0 ? static_cast<double>(sum) / static_cast<double>(cnt) : 0.0);
            if (ip == targetIp_) {
                reached = true;
            }
        }
        completedHops = qMax(completedHops, index);
        hops.push_back(hop);
    }

    QVariantMap out;
    out.insert(QStringLiteral("hops"), hops);
    out.insert(QStringLiteral("completedHops"), completedHops);
    out.insert(QStringLiteral("destinationReached"), reached);
    lastSnapshot_ = out;
}

} // namespace gpd::platform
