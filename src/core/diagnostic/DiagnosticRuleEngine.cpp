#include "core/diagnostic/DiagnosticRuleEngine.h"

#include <QDateTime>

namespace gpd::core {

namespace {

DiagnosticFinding makeFinding(const QString& sectionId,
                              const QString& title,
                              const QString& metric,
                              const DiagnosticStatus status,
                              const QString& recommendation = QString()) {
    DiagnosticFinding finding;
    finding.sectionId = sectionId;
    finding.title = title;
    finding.metric = metric;
    finding.status = status;
    finding.recommendation = recommendation;
    finding.timestampMs = QDateTime::currentMSecsSinceEpoch();
    return finding;
}

QVariantMap nestedMap(const QVariantMap& snapshot, const QString& key) {
    return snapshot.value(key).toMap();
}

double mapNumber(const QVariantMap& m, const QString& key, const double fallback = 0.0) {
    return m.value(key, fallback).toDouble();
}

} // namespace

DiagnosticReport DiagnosticRuleEngine::buildReport(const QString& targetIp,
                                                   const int targetPort,
                                                   const QString& processName,
                                                   const QHash<QString, QVariantMap>& probeSnapshots,
                                                   const ConnectionInfo* connectionInfo) const {
    DiagnosticReport report;
    report.startedAtMs = QDateTime::currentMSecsSinceEpoch();
    report.targetIp = targetIp;
    report.targetPort = targetPort;
    report.targetProcessName = processName;

    report.sections = {
        evaluateLocal(probeSnapshots),
        evaluateFirstHop(probeSnapshots),
        evaluateIsp(probeSnapshots),
        evaluateVpn(probeSnapshots, connectionInfo),
        evaluateGameServer(probeSnapshots),
        evaluateBufferbloat(probeSnapshots),
        evaluateBackground(probeSnapshots),
    };

    QVector<DiagnosticStatus> statuses;
    statuses.reserve(report.sections.size());
    for (const auto& section : report.sections) {
        statuses.push_back(section.overallStatus);
    }
    report.overallStatus = combineStatuses(statuses);
    bool hasCriticalUnknown = false;
    for (const auto& section : report.sections) {
        const bool critical = section.id == QStringLiteral("first_hop") || section.id == QStringLiteral("bufferbloat") || section.id == QStringLiteral("game_server");
        if (critical && section.overallStatus == DiagnosticStatus::Unknown) {
            hasCriticalUnknown = true;
            break;
        }
    }
    if (hasCriticalUnknown && report.overallStatus == DiagnosticStatus::Ok) {
        report.overallStatus = DiagnosticStatus::Warning;
    }
    report.completedAtMs = QDateTime::currentMSecsSinceEpoch();
    return report;
}

DiagnosticSection DiagnosticRuleEngine::evaluateLocal(const QHash<QString, QVariantMap>& snapshots) const {
    DiagnosticSection section;
    section.id = QStringLiteral("local");
    section.title = QStringLiteral("Локальная сеть");
    section.overallStatus = DiagnosticStatus::Ok;

    const auto wifi = snapshots.value(QStringLiteral("wifi_metrics"));
    if (!wifi.isEmpty()) {
        const int rssi = wifi.value(QStringLiteral("rssidBm")).toInt(0);
        const int speed = wifi.value(QStringLiteral("linkSpeedMbps")).toInt(0);
        if (rssi < -80) {
            section.findings.push_back(makeFinding(section.id, QStringLiteral("Сигнал Wi-Fi очень слабый"),
                                                   QStringLiteral("RSSI: %1 dBm").arg(rssi),
                                                   DiagnosticStatus::Problem,
                                                   QStringLiteral("Подойдите ближе к точке доступа или используйте Ethernet.")));
        } else if (rssi < -70) {
            section.findings.push_back(makeFinding(section.id, QStringLiteral("Сигнал Wi-Fi слабый"),
                                                   QStringLiteral("RSSI: %1 dBm").arg(rssi),
                                                   DiagnosticStatus::Warning,
                                                   QStringLiteral("Сигнал слабый; сократите расстояние до точки доступа.")));
        }
        if (speed > 0 && speed < 50) {
            section.findings.push_back(makeFinding(section.id, QStringLiteral("Низкая скорость Wi-Fi линка"),
                                                   QStringLiteral("Link speed: %1 Mbps").arg(speed),
                                                   DiagnosticStatus::Warning,
                                                   QStringLiteral("Возможны помехи; проверьте загруженность канала.")));
        }
    }

    const auto adapter = snapshots.value(QStringLiteral("adapter_errors"));
    if (!adapter.isEmpty()) {
        const double inErr = mapNumber(adapter, QStringLiteral("inErrorsPerSec"));
        const double outErr = mapNumber(adapter, QStringLiteral("outErrorsPerSec"));
        const double total = inErr + outErr;
        if (total > 1.0) {
            section.findings.push_back(makeFinding(section.id, QStringLiteral("Высокий уровень ошибок адаптера"),
                                                   QStringLiteral("Errors/sec: %1").arg(QString::number(total, 'f', 2)),
                                                   DiagnosticStatus::Problem,
                                                   QStringLiteral("Обновите драйвер и проверьте кабель/состояние адаптера.")));
        } else if (total > 0.1) {
            section.findings.push_back(makeFinding(section.id, QStringLiteral("У адаптера есть ошибки"),
                                                   QStringLiteral("Errors/sec: %1").arg(QString::number(total, 'f', 2)),
                                                   DiagnosticStatus::Warning,
                                                   QStringLiteral("Проверьте адаптер и попробуйте подключение по Ethernet.")));
        }
    }

    const auto cpu = snapshots.value(QStringLiteral("cpu_pressure"));
    if (!cpu.isEmpty()) {
        const double processCpu = mapNumber(cpu, QStringLiteral("processCpuPercent"));
        if (processCpu > 90.0) {
            section.findings.push_back(makeFinding(section.id, QStringLiteral("Игровой процесс упирается в CPU"),
                                                   QStringLiteral("Process CPU: %1%").arg(QString::number(processCpu, 'f', 1)),
                                                   DiagnosticStatus::Warning,
                                                   QStringLiteral("Фризы могут быть связаны с игрой, а не с сетью.")));
        }
    }

    if (section.findings.isEmpty()) {
        section.findings.push_back(makeFinding(section.id, QStringLiteral("Локальные метрики в норме"), QStringLiteral("Проблем не обнаружено"), DiagnosticStatus::Ok));
    }
    QVector<DiagnosticStatus> statuses;
    for (const auto& f : section.findings) {
        statuses.push_back(f.status);
    }
    section.overallStatus = combineStatuses(statuses);
    return section;
}

DiagnosticSection DiagnosticRuleEngine::evaluateFirstHop(const QHash<QString, QVariantMap>& snapshots) const {
    DiagnosticSection section;
    section.id = QStringLiteral("first_hop");
    section.title = QStringLiteral("Первый хоп (роутер)");
    const auto anchor = snapshots.value(QStringLiteral("anchor_ping"));
    const auto lossProbe = snapshots.value(QStringLiteral("packet_loss"));
    const auto firstHopLoss = nestedMap(lossProbe, QStringLiteral("first_hop"));
    if (!firstHopLoss.isEmpty()) {
        const double loss = mapNumber(firstHopLoss, QStringLiteral("lossPercent"), -1.0);
        const double avg = mapNumber(firstHopLoss, QStringLiteral("avgRttMs"), -1.0);
        const QString ip = firstHopLoss.value(QStringLiteral("ip")).toString();
        if (loss >= 0.0) {
            section.findings.push_back(makeFinding(section.id,
                                                   QStringLiteral("Потери до первого хопа"),
                                                   QStringLiteral("Шлюз %1, loss %2%, avg RTT %3 ms")
                                                       .arg(ip, QString::number(loss, 'f', 1), QString::number(avg, 'f', 1)),
                                                   loss >= 1.0 ? DiagnosticStatus::Problem : DiagnosticStatus::Ok,
                                                   loss >= 1.0 ? QStringLiteral("Проверьте роутер, кабель/Wi-Fi и локальные помехи.") : QString()));
        }
    }
    const auto gw = nestedMap(anchor, QStringLiteral("gateway"));
    if (gw.isEmpty() && section.findings.isEmpty()) {
        section.overallStatus = DiagnosticStatus::Unknown;
        return section;
    }
    if (!gw.isEmpty()) {
        const double rtt = mapNumber(gw, QStringLiteral("rttMs"));
        const double jitter = mapNumber(gw, QStringLiteral("jitterMs"));
        const double loss = mapNumber(gw, QStringLiteral("lossPercent"));
        section.findings.push_back(makeFinding(section.id, QStringLiteral("Состояние шлюза"),
                                               QStringLiteral("RTT %1 ms, jitter %2 ms, loss %3%")
                                                   .arg(QString::number(rtt, 'f', 1), QString::number(jitter, 'f', 1), QString::number(loss, 'f', 1)),
                                               loss > 0.5 ? DiagnosticStatus::Problem : (jitter > 5.0 ? DiagnosticStatus::Warning : DiagnosticStatus::Ok)));
    }
    QVector<DiagnosticStatus> statuses;
    for (const auto& f : section.findings) {
        statuses.push_back(f.status);
    }
    section.overallStatus = combineStatuses(statuses);
    return section;
}

DiagnosticSection DiagnosticRuleEngine::evaluateIsp(const QHash<QString, QVariantMap>& snapshots) const {
    DiagnosticSection section;
    section.id = QStringLiteral("isp");
    section.title = QStringLiteral("Провайдер и интернет-маршрут");
    const auto anchor = snapshots.value(QStringLiteral("anchor_ping"));
    const auto a11 = nestedMap(anchor, QStringLiteral("anchor_1_1_1_1"));
    const auto a88 = nestedMap(anchor, QStringLiteral("anchor_8_8_8_8"));
    if (a11.isEmpty() || a88.isEmpty()) {
        section.overallStatus = DiagnosticStatus::Unknown;
        return section;
    }
    const double rtt11 = mapNumber(a11, QStringLiteral("rttMs"));
    const double rtt88 = mapNumber(a88, QStringLiteral("rttMs"));
    const double loss11 = mapNumber(a11, QStringLiteral("lossPercent"));
    const double loss88 = mapNumber(a88, QStringLiteral("lossPercent"));
    if (qAbs(rtt11 - rtt88) > 50.0) {
        section.findings.push_back(makeFinding(section.id, QStringLiteral("RTT якорей сильно различается"),
                                               QStringLiteral("1.1.1.1=%1 ms, 8.8.8.8=%2 ms").arg(QString::number(rtt11, 'f', 1), QString::number(rtt88, 'f', 1)),
                                               DiagnosticStatus::Warning,
                                               QStringLiteral("Возможно асимметричная маршрутизация или peering-проблема у провайдера.")));
    }
    if (loss11 > 1.0 || loss88 > 1.0) {
        section.findings.push_back(makeFinding(section.id, QStringLiteral("Есть потери на интернет-якорях"),
                                               QStringLiteral("Loss: %1% / %2%").arg(QString::number(loss11, 'f', 1), QString::number(loss88, 'f', 1)),
                                               DiagnosticStatus::Problem,
                                               QStringLiteral("Потери, вероятно, вне локальной сети.")));
    }
    const auto hop = snapshots.value(QStringLiteral("hop_probe"));
    if (!hop.isEmpty()) {
        const int completedHops = hop.value(QStringLiteral("completedHops")).toInt();
        const bool reached = hop.value(QStringLiteral("destinationReached")).toBool();
        section.findings.push_back(makeFinding(section.id,
                                               QStringLiteral("Результат трассировки"),
                                               QStringLiteral("Хопов: %1, цель достигнута: %2").arg(completedHops).arg(reached ? QStringLiteral("да") : QStringLiteral("нет")),
                                               reached ? DiagnosticStatus::Info : DiagnosticStatus::Warning));
    }
    if (section.findings.isEmpty()) {
        section.findings.push_back(makeFinding(section.id, QStringLiteral("Якоря выглядят стабильно"), QStringLiteral("Существенных аномалий у провайдера не видно"), DiagnosticStatus::Ok));
    }
    QVector<DiagnosticStatus> statuses;
    for (const auto& f : section.findings) {
        statuses.push_back(f.status);
    }
    section.overallStatus = combineStatuses(statuses);
    return section;
}

DiagnosticSection DiagnosticRuleEngine::evaluateVpn(const QHash<QString, QVariantMap>& snapshots, const ConnectionInfo* ci) const {
    DiagnosticSection section;
    section.id = QStringLiteral("vpn");
    section.title = QStringLiteral("VPN-туннель");
    const auto vpnRoute = snapshots.value(QStringLiteral("vpn_route"));
    const bool fullTunnel = vpnRoute.value(QStringLiteral("fullTunnelDetected")).toBool();
    const bool clashNonDirect = ci != nullptr && ci->clashTracked && ci->clashOutbound.compare(QStringLiteral("DIRECT"), Qt::CaseInsensitive) != 0;
    const bool inferredVpn = ci != nullptr && (ci->routedThroughKind == InterfaceKind::VpnTunnel || clashNonDirect);
    if (!fullTunnel && !inferredVpn) {
        section.overallStatus = DiagnosticStatus::Info;
        section.findings.push_back(makeFinding(section.id, QStringLiteral("Активный VPN-маршрут не обнаружен"), QStringLiteral("VPN-проверки пропущены"), DiagnosticStatus::Info));
        return section;
    }
    if (fullTunnel) {
        const auto d4 = nestedMap(vpnRoute, QStringLiteral("defaultIpv4"));
        const auto d6 = nestedMap(vpnRoute, QStringLiteral("defaultIpv6"));
        QString metric = QStringLiteral("Full-tunnel по default route");
        if (!d4.isEmpty()) {
            metric += QStringLiteral(", IPv4 ifIndex=%1 nextHop=%2").arg(d4.value(QStringLiteral("ifIndex")).toInt()).arg(d4.value(QStringLiteral("nextHop")).toString());
        }
        if (!d6.isEmpty()) {
            metric += QStringLiteral(", IPv6 ifIndex=%1 nextHop=%2").arg(d6.value(QStringLiteral("ifIndex")).toInt()).arg(d6.value(QStringLiteral("nextHop")).toString());
        }
        section.findings.push_back(makeFinding(section.id, QStringLiteral("Обнаружен full-tunnel VPN"), metric, DiagnosticStatus::Info));
    }
    const auto anchor = snapshots.value(QStringLiteral("anchor_ping"));
    const auto t = nestedMap(anchor, QStringLiteral("target"));
    const auto a = nestedMap(anchor, QStringLiteral("anchor_1_1_1_1"));
    if (t.isEmpty() || a.isEmpty()) {
        section.overallStatus = DiagnosticStatus::Unknown;
        return section;
    }
    const double jitterDelta = mapNumber(t, QStringLiteral("jitterMs")) - mapNumber(a, QStringLiteral("jitterMs"));
    const double rttDelta = mapNumber(t, QStringLiteral("rttMs")) - mapNumber(a, QStringLiteral("rttMs"));
    if (rttDelta > 30.0) {
        section.findings.push_back(makeFinding(section.id, QStringLiteral("VPN добавляет задержку"),
                                               QStringLiteral("Delta RTT: +%1 ms").arg(QString::number(rttDelta, 'f', 1)),
                                               DiagnosticStatus::Info));
    }
    if (jitterDelta > 20.0) {
        section.findings.push_back(makeFinding(section.id, QStringLiteral("VPN добавляет джиттер"),
                                               QStringLiteral("Delta jitter: +%1 ms").arg(QString::number(jitterDelta, 'f', 1)),
                                               DiagnosticStatus::Problem,
                                               QStringLiteral("Попробуйте другой VPN-сервер.")));
    }
    if (section.findings.isEmpty()) {
        section.findings.push_back(makeFinding(section.id, QStringLiteral("VPN-путь выглядит приемлемо"), QStringLiteral("Существенных VPN-аномалий не обнаружено"), DiagnosticStatus::Ok));
    }
    QVector<DiagnosticStatus> statuses;
    for (const auto& f : section.findings) {
        statuses.push_back(f.status);
    }
    section.overallStatus = combineStatuses(statuses);
    return section;
}

DiagnosticSection DiagnosticRuleEngine::evaluateGameServer(const QHash<QString, QVariantMap>& snapshots) const {
    DiagnosticSection section;
    section.id = QStringLiteral("game_server");
    section.title = QStringLiteral("Игровой сервер");
    const auto anchor = snapshots.value(QStringLiteral("anchor_ping"));
    const auto lossProbe = snapshots.value(QStringLiteral("packet_loss"));
    const auto t = nestedMap(anchor, QStringLiteral("target"));
    const auto targetLoss = nestedMap(lossProbe, QStringLiteral("target"));
    if (t.isEmpty() && targetLoss.isEmpty()) {
        section.overallStatus = DiagnosticStatus::Unknown;
        section.findings.push_back(makeFinding(section.id,
                                               QStringLiteral("Потери игрового потока не измерены напрямую"),
                                               QStringLiteral("Loss-проба недоступна"),
                                               DiagnosticStatus::Info,
                                               QStringLiteral("Запустите полную диагностику для активной игровой сессии.")));
        return section;
    }
    if (!t.isEmpty()) {
        const double rtt = mapNumber(t, QStringLiteral("rttMs"), -1.0);
        const double jitter = mapNumber(t, QStringLiteral("jitterMs"));
        const double loss = mapNumber(t, QStringLiteral("lossPercent"));
        if (rtt < 0.0) {
            section.findings.push_back(makeFinding(section.id,
                                                   QStringLiteral("RTT сервера недоступен"),
                                                   QStringLiteral("Нет валидных измерений RTT для цели"),
                                                   DiagnosticStatus::Unknown,
                                                   QStringLiteral("Убедитесь, что выбран активный игровой поток с реальным remote IP.")));
        } else {
            DiagnosticStatus rttStatus = DiagnosticStatus::Ok;
            if (rtt > 100.0) {
                rttStatus = DiagnosticStatus::Problem;
            } else if (rtt > 50.0) {
                rttStatus = DiagnosticStatus::Warning;
            }
            section.findings.push_back(makeFinding(section.id, QStringLiteral("RTT сервера"), QStringLiteral("RTT: %1 ms").arg(QString::number(rtt, 'f', 1)), rttStatus));
        }
        if (jitter > 30.0) {
            section.findings.push_back(makeFinding(section.id, QStringLiteral("Высокий джиттер"), QStringLiteral("Джиттер: %1 ms").arg(QString::number(jitter, 'f', 1)), DiagnosticStatus::Problem));
        }
        if (loss > 1.0) {
            section.findings.push_back(makeFinding(section.id, QStringLiteral("Потери пакетов влияют на игру"), QStringLiteral("Потери: %1%").arg(QString::number(loss, 'f', 1)), DiagnosticStatus::Problem));
        }
    }

    if (!targetLoss.isEmpty()) {
        const double directLoss = mapNumber(targetLoss, QStringLiteral("lossPercent"), -1.0);
        const double avg = mapNumber(targetLoss, QStringLiteral("avgRttMs"), -1.0);
        if (directLoss >= 0.0) {
            section.findings.push_back(makeFinding(section.id,
                                                   QStringLiteral("Прямая loss-проба до сервера"),
                                                   QStringLiteral("Loss %1%, avg RTT %2 ms")
                                                       .arg(QString::number(directLoss, 'f', 1), QString::number(avg, 'f', 1)),
                                                   directLoss >= 1.0 ? DiagnosticStatus::Problem : DiagnosticStatus::Ok,
                                                   directLoss >= 1.0 ? QStringLiteral("Есть потери до сервера; проверьте маршрут/VPN/канал.") : QString()));
        }
    } else {
        section.findings.push_back(makeFinding(section.id,
                                               QStringLiteral("Потери игрового потока не измерены напрямую"),
                                               QStringLiteral("Loss-проба недоступна"),
                                               DiagnosticStatus::Info,
                                               QStringLiteral("Запустите полную диагностику для активной игровой сессии.")));
    }
    QVector<DiagnosticStatus> statuses;
    for (const auto& f : section.findings) {
        statuses.push_back(f.status);
    }
    section.overallStatus = combineStatuses(statuses);
    return section;
}

DiagnosticSection DiagnosticRuleEngine::evaluateBufferbloat(const QHash<QString, QVariantMap>& snapshots) const {
    DiagnosticSection section;
    section.id = QStringLiteral("bufferbloat");
    section.title = QStringLiteral("Буферблоат");
    const auto b = snapshots.value(QStringLiteral("bufferbloat"));
    if (b.isEmpty()) {
        section.overallStatus = DiagnosticStatus::Unknown;
        return section;
    }
    const double idle = mapNumber(b, QStringLiteral("idleRttMs"));
    const double loaded = mapNumber(b, QStringLiteral("loadedRttMs"));
    const double increase = loaded - idle;
    DiagnosticStatus s = DiagnosticStatus::Ok;
    if (increase > 100.0) {
        s = DiagnosticStatus::Severe;
    } else if (increase >= 30.0) {
        s = DiagnosticStatus::Warning;
    }
    section.findings.push_back(makeFinding(section.id, QStringLiteral("Задержка под нагрузкой"),
                                           QStringLiteral("Простой %1 ms, под нагрузкой %2 ms, прирост +%3 ms")
                                               .arg(QString::number(idle, 'f', 1), QString::number(loaded, 'f', 1), QString::number(increase, 'f', 1)),
                                           s,
                                           s == DiagnosticStatus::Severe ? QStringLiteral("Включите SQM/QoS на роутере.") : QString()));
    section.overallStatus = s;
    return section;
}

DiagnosticSection DiagnosticRuleEngine::evaluateBackground(const QHash<QString, QVariantMap>& snapshots) const {
    DiagnosticSection section;
    section.id = QStringLiteral("background");
    section.title = QStringLiteral("Фоновый трафик");
    const auto bg = snapshots.value(QStringLiteral("background_traffic"));
    if (bg.isEmpty()) {
        section.overallStatus = DiagnosticStatus::Unknown;
        return section;
    }
    const double total = mapNumber(bg, QStringLiteral("totalBackgroundMbps"));
    const double threshold = mapNumber(bg, QStringLiteral("warningThresholdMbps"), 20.0);
    const auto talkers = bg.value(QStringLiteral("topTalkers")).toList();
    QString topText;
    if (!talkers.isEmpty()) {
        const auto top = talkers.first().toMap();
        topText = QStringLiteral(" Топ: %1 (%2 Mbps)")
                      .arg(top.value(QStringLiteral("process")).toString(),
                           QString::number(top.value(QStringLiteral("bandwidthMbps")).toDouble(), 'f', 1));
    }
    if (total > (threshold * 2.0)) {
        section.findings.push_back(makeFinding(section.id, QStringLiteral("Фоновый трафик перегружает канал"),
                                               QStringLiteral("Фон: %1 Mbps.%2").arg(QString::number(total, 'f', 1), topText),
                                               DiagnosticStatus::Problem,
                                               QStringLiteral("Сильный фоновый трафик; остановите загрузки/обновления.")));
    } else if (total > threshold) {
        section.findings.push_back(makeFinding(section.id, QStringLiteral("Высокий фоновый трафик"),
                                               QStringLiteral("Фон: %1 Mbps.%2").arg(QString::number(total, 'f', 1), topText),
                                               DiagnosticStatus::Warning,
                                               QStringLiteral("Поставьте на паузу крупные загрузки во время игры.")));
    } else {
        section.findings.push_back(makeFinding(section.id, QStringLiteral("Фоновый трафик низкий"),
                                               QStringLiteral("Фон: %1 Mbps.%2").arg(QString::number(total, 'f', 1), topText),
                                               DiagnosticStatus::Ok));
    }
    section.overallStatus = combineStatuses({section.findings[0].status});
    return section;
}

DiagnosticStatus DiagnosticRuleEngine::combineStatuses(const QVector<DiagnosticStatus>& statuses) {
    int problems = 0;
    bool hasSevere = false;
    bool hasWarning = false;
    bool hasInfo = false;
    bool hasOk = false;
    for (const auto status : statuses) {
        if (status == DiagnosticStatus::Severe) {
            hasSevere = true;
        } else if (status == DiagnosticStatus::Problem) {
            ++problems;
        } else if (status == DiagnosticStatus::Warning) {
            hasWarning = true;
        } else if (status == DiagnosticStatus::Info) {
            hasInfo = true;
        } else if (status == DiagnosticStatus::Ok) {
            hasOk = true;
        }
    }
    if (hasSevere || problems >= 2) {
        return DiagnosticStatus::Severe;
    }
    if (problems == 1) {
        return DiagnosticStatus::Problem;
    }
    if (hasWarning) {
        return DiagnosticStatus::Warning;
    }
    if (hasOk || hasInfo) {
        return hasOk ? DiagnosticStatus::Ok : DiagnosticStatus::Info;
    }
    return DiagnosticStatus::Unknown;
}

} // namespace gpd::core
