#include "core/diagnostic/DiagnosticRuleEngine.h"

#include <QDateTime>
#include <QStringList>

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
        evaluateGameServer(probeSnapshots, connectionInfo),
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
        const QString ssid = wifi.value(QStringLiteral("ssid")).toString();
        DiagnosticStatus wifiStatus = DiagnosticStatus::Ok;
        QString wifiAdvice;
        if (rssi < -80) {
            wifiStatus = DiagnosticStatus::Problem;
            wifiAdvice = QStringLiteral("Подойдите ближе к точке доступа или используйте Ethernet.");
        } else if (rssi < -70) {
            wifiStatus = DiagnosticStatus::Warning;
            wifiAdvice = QStringLiteral("Сигнал слабый; сократите расстояние до точки доступа.");
        }
        if (speed > 0 && speed < 50 && wifiStatus == DiagnosticStatus::Ok) {
            wifiStatus = DiagnosticStatus::Warning;
            wifiAdvice = QStringLiteral("Возможны помехи; проверьте загруженность канала.");
        }
        section.findings.push_back(makeFinding(section.id,
                                               QStringLiteral("Wi-Fi"),
                                               QStringLiteral("%1, RSSI %2 dBm, link %3 Mbps").arg(ssid.isEmpty() ? QStringLiteral("(SSID неизвестен)") : ssid).arg(rssi).arg(speed),
                                               wifiStatus,
                                               wifiAdvice));
    } else {
        section.findings.push_back(makeFinding(section.id, QStringLiteral("Канал доступа"), QStringLiteral("Подключение не через Wi-Fi или метрики Wi-Fi недоступны"), DiagnosticStatus::Info));
    }

    const auto adapter = snapshots.value(QStringLiteral("adapter_errors"));
    if (!adapter.isEmpty()) {
        const double inErr = mapNumber(adapter, QStringLiteral("inErrorsPerSec"));
        const double outErr = mapNumber(adapter, QStringLiteral("outErrorsPerSec"));
        const double total = inErr + outErr;
        DiagnosticStatus adapterStatus = DiagnosticStatus::Ok;
        QString advice;
        if (total > 1.0) {
            adapterStatus = DiagnosticStatus::Problem;
            advice = QStringLiteral("Обновите драйвер и проверьте кабель/состояние адаптера.");
        } else if (total > 0.1) {
            adapterStatus = DiagnosticStatus::Warning;
            advice = QStringLiteral("Проверьте адаптер и попробуйте подключение по Ethernet.");
        }
        section.findings.push_back(makeFinding(section.id,
                                               QStringLiteral("Сетевой адаптер"),
                                               QStringLiteral("Ошибок %1/сек").arg(QString::number(total, 'f', 2)),
                                               adapterStatus,
                                               advice));
    }

    const auto cpu = snapshots.value(QStringLiteral("cpu_pressure"));
    if (!cpu.isEmpty()) {
        const double processCpu = mapNumber(cpu, QStringLiteral("processCpuPercent"));
        const double systemCpu = mapNumber(cpu, QStringLiteral("systemCpuPercent"));
        const DiagnosticStatus cpuStatus = (processCpu > 90.0 || systemCpu > 95.0) ? DiagnosticStatus::Warning : DiagnosticStatus::Ok;
        section.findings.push_back(makeFinding(section.id,
                                               QStringLiteral("CPU"),
                                               QStringLiteral("процесс %1%, система %2%").arg(QString::number(processCpu, 'f', 1), QString::number(systemCpu, 'f', 1)),
                                               cpuStatus,
                                               cpuStatus == DiagnosticStatus::Warning ? QStringLiteral("Фризы могут быть связаны с CPU-нагрузкой.") : QString()));
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
    const auto aCf = nestedMap(anchor, QStringLiteral("anchor_cf_ntp"));
    const auto aGa = nestedMap(anchor, QStringLiteral("anchor_google_ntp_a"));
    const auto aGb = nestedMap(anchor, QStringLiteral("anchor_google_ntp_b"));
    const auto aNist = nestedMap(anchor, QStringLiteral("anchor_nist_ntp"));
    if (aCf.isEmpty() || aGa.isEmpty() || aGb.isEmpty() || aNist.isEmpty()) {
        section.overallStatus = DiagnosticStatus::Unknown;
        return section;
    }
    const double rttCf = mapNumber(aCf, QStringLiteral("rttMs"));
    const double rttGa = mapNumber(aGa, QStringLiteral("rttMs"));
    const double lossCf = mapNumber(aCf, QStringLiteral("lossPercent"));
    const double lossGa = mapNumber(aGa, QStringLiteral("lossPercent"));
    const double jitterCf = mapNumber(aCf, QStringLiteral("jitterMs"));
    const double jitterGa = mapNumber(aGa, QStringLiteral("jitterMs"));
    const double jitterGb = mapNumber(aGb, QStringLiteral("jitterMs"));
    const double jitterNist = mapNumber(aNist, QStringLiteral("jitterMs"));
    const QString physicalLocalIp = anchor.value(QStringLiteral("physicalLocalIp")).toString();
    const QString headerSuffix = physicalLocalIp.isEmpty()
        ? QStringLiteral("")
        : QStringLiteral(" — direct path (bind %1)").arg(physicalLocalIp);
    section.findings.push_back(makeFinding(section.id,
                                           QStringLiteral("Cloudflare NTP (162.159.200.123)") + headerSuffix,
                                           QStringLiteral("RTT %1 ms, jitter %2 ms, loss %3%")
                                               .arg(QString::number(rttCf, 'f', 1),
                                                    QString::number(jitterCf, 'f', 1),
                                                    QString::number(lossCf, 'f', 1)),
                                           DiagnosticStatus::Info));
    section.findings.push_back(makeFinding(section.id,
                                           QStringLiteral("Google NTP (216.239.35.0)"),
                                           QStringLiteral("RTT %1 ms, jitter %2 ms, loss %3%")
                                               .arg(QString::number(rttGa, 'f', 1),
                                                    QString::number(jitterGa, 'f', 1),
                                                    QString::number(lossGa, 'f', 1)),
                                           DiagnosticStatus::Info));
    section.findings.push_back(makeFinding(section.id,
                                           QStringLiteral("Google NTP (216.239.35.4)"),
                                           QStringLiteral("RTT %1 ms, jitter %2 ms, loss %3%")
                                               .arg(QString::number(mapNumber(aGb, QStringLiteral("rttMs")), 'f', 1),
                                                    QString::number(jitterGb, 'f', 1),
                                                    QString::number(mapNumber(aGb, QStringLiteral("lossPercent")), 'f', 1)),
                                           DiagnosticStatus::Info));
    section.findings.push_back(makeFinding(section.id,
                                            QStringLiteral("NIST NTP (132.163.97.4)"),
                                            QStringLiteral("RTT %1 ms, jitter %2 ms, loss %3%")
                                                .arg(QString::number(mapNumber(aNist, QStringLiteral("rttMs")), 'f', 1),
                                                     QString::number(jitterNist, 'f', 1),
                                                     QString::number(mapNumber(aNist, QStringLiteral("lossPercent")), 'f', 1)),
                                            DiagnosticStatus::Info));
    double jitterSum = 0.0;
    int jitterCount = 0;
    for (const double j : {jitterCf, jitterGa, jitterGb, jitterNist}) {
        if (j > 0.0) {
            jitterSum += j;
            ++jitterCount;
        }
    }
    const double directJitterAvg = jitterCount > 0 ? jitterSum / static_cast<double>(jitterCount) : 0.0;
    if (directJitterAvg > 20.0) {
        section.findings.push_back(makeFinding(section.id,
                                               QStringLiteral("Высокий джиттер на direct-якорях"),
                                               QStringLiteral("Средний jitter на физическом интерфейсе: %1 ms").arg(QString::number(directJitterAvg, 'f', 1)),
                                               DiagnosticStatus::Problem,
                                               QStringLiteral("Проверьте Wi-Fi/роутер/CPU: проблема в last-mile, не на VPN.")));
    } else if (directJitterAvg > 8.0) {
        section.findings.push_back(makeFinding(section.id,
                                               QStringLiteral("Заметный джиттер на direct-якорях"),
                                               QStringLiteral("Средний jitter direct: %1 ms").arg(QString::number(directJitterAvg, 'f', 1)),
                                               DiagnosticStatus::Warning));
    }
    const double lossGb = mapNumber(aGb, QStringLiteral("lossPercent"));
    const double lossNist = mapNumber(aNist, QStringLiteral("lossPercent"));
    int reachableCount = 0;
    int lossyCount = 0;
    for (const double loss : {lossCf, lossGa, lossGb, lossNist}) {
        if (loss < 100.0) {
            ++reachableCount;
        }
        if (loss > 5.0) {
            ++lossyCount;
        }
    }
    const bool rttCfValid = rttCf > 0.0 && lossCf < 50.0;
    const bool rttGaValid = rttGa > 0.0 && lossGa < 50.0;
    if (rttCfValid && rttGaValid && qAbs(rttCf - rttGa) > 50.0) {
        section.findings.push_back(makeFinding(section.id, QStringLiteral("RTT якорей сильно различается"),
                                               QStringLiteral("Cloudflare=%1 ms, Google=%2 ms").arg(QString::number(rttCf, 'f', 1), QString::number(rttGa, 'f', 1)),
                                               DiagnosticStatus::Warning,
                                               QStringLiteral("Возможно асимметричная маршрутизация или peering-проблема у провайдера/VPN.")));
    }
    if (lossyCount >= 3) {
        section.findings.push_back(makeFinding(section.id, QStringLiteral("Потери на большинстве интернет-якорей"),
                                               QStringLiteral("Якорей с заметными потерями: %1 из 4").arg(lossyCount),
                                               DiagnosticStatus::Problem,
                                               QStringLiteral("Потери, вероятно, вне локальной сети или на стороне VPN.")));
    } else if (lossyCount >= 1 && reachableCount >= 3) {
        QStringList lossy;
        if (lossCf > 5.0) lossy << QStringLiteral("Cloudflare %1%").arg(QString::number(lossCf, 'f', 0));
        if (lossGa > 5.0) lossy << QStringLiteral("Google-A %1%").arg(QString::number(lossGa, 'f', 0));
        if (lossGb > 5.0) lossy << QStringLiteral("Google-B %1%").arg(QString::number(lossGb, 'f', 0));
        if (lossNist > 5.0) lossy << QStringLiteral("NIST %1%").arg(QString::number(lossNist, 'f', 0));
        section.findings.push_back(makeFinding(section.id,
                                               QStringLiteral("Часть NTP-якорей не отвечает"),
                                               QStringLiteral("%1 — вероятно блок/throttle на стороне сервера, остальные якоря работают.").arg(lossy.join(QStringLiteral(", "))),
                                               DiagnosticStatus::Info));
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
    const auto tunnelLoadEarly = snapshots.value(QStringLiteral("tunnel_load"));
    const bool tunnelInterfaceUp = tunnelLoadEarly.value(QStringLiteral("tunnelFound")).toBool();
    const bool splitTunnelInferred = !fullTunnel && !inferredVpn && tunnelInterfaceUp;
    if (!fullTunnel && !inferredVpn && !tunnelInterfaceUp) {
        section.overallStatus = DiagnosticStatus::Info;
        section.findings.push_back(makeFinding(section.id, QStringLiteral("Активный VPN-маршрут не обнаружен"), QStringLiteral("VPN-проверки пропущены"), DiagnosticStatus::Info));
        return section;
    }
    if (splitTunnelInferred) {
        section.findings.push_back(makeFinding(section.id,
                                               QStringLiteral("Split-tunnel: игра идёт мимо VPN"),
                                               QStringLiteral("VPN-интерфейс активен, но игровой поток идёт direct. Сравниваем direct vs tunneled якоря."),
                                               DiagnosticStatus::Info));
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
    const auto tunnelLoad = snapshots.value(QStringLiteral("tunnel_load"));
    const auto t = nestedMap(anchor, QStringLiteral("target"));
    const auto aDirect = nestedMap(anchor, QStringLiteral("anchor_cf_ntp"));
    const auto aTunneled = nestedMap(anchor, QStringLiteral("anchor_cf_ntp_tunneled"));

    if (!aDirect.isEmpty() && !aTunneled.isEmpty()) {
        const double rttDirect = mapNumber(aDirect, QStringLiteral("rttMs"));
        const double rttTunneled = mapNumber(aTunneled, QStringLiteral("rttMs"));
        const double jitDirect = mapNumber(aDirect, QStringLiteral("jitterMs"));
        const double jitTunneled = mapNumber(aTunneled, QStringLiteral("jitterMs"));
        const double rttOverhead = rttTunneled - rttDirect;
        const double jitOverhead = jitTunneled - jitDirect;
        if (rttDirect > 0.0 && rttTunneled > 0.0) {
            section.findings.push_back(makeFinding(
                section.id,
                QStringLiteral("VPN накладные расходы (Cloudflare NTP)"),
                QStringLiteral("Direct %1 ms -> Tunneled %2 ms (дельта +%3 ms), jitter direct %4 ms -> tunneled %5 ms")
                    .arg(QString::number(rttDirect, 'f', 1),
                         QString::number(rttTunneled, 'f', 1),
                         QString::number(rttOverhead, 'f', 1),
                         QString::number(jitDirect, 'f', 1),
                         QString::number(jitTunneled, 'f', 1)),
                rttOverhead > 100.0 ? DiagnosticStatus::Warning : DiagnosticStatus::Info));
        }
        if (jitOverhead > 15.0 && jitTunneled > 20.0) {
            section.findings.push_back(makeFinding(section.id,
                                                   QStringLiteral("VPN добавляет джиттер"),
                                                   QStringLiteral("Delta jitter: +%1 ms (direct %2 ms, tunneled %3 ms)")
                                                       .arg(QString::number(jitOverhead, 'f', 1),
                                                            QString::number(jitDirect, 'f', 1),
                                                            QString::number(jitTunneled, 'f', 1)),
                                                   DiagnosticStatus::Problem,
                                                   QStringLiteral("Проблема на стороне VPN. Попробуйте другой сервер или протокол.")));
        }
    }

    if (!tunnelLoad.isEmpty()) {
        const bool tunnelFound = tunnelLoad.value(QStringLiteral("tunnelFound")).toBool();
        const double tunOut = mapNumber(tunnelLoad, QStringLiteral("tunnelOutMbps"));
        const double tunIn = mapNumber(tunnelLoad, QStringLiteral("tunnelInMbps"));
        const double physOut = mapNumber(tunnelLoad, QStringLiteral("physicalOutMbps"));
        const double physIn = mapNumber(tunnelLoad, QStringLiteral("physicalInMbps"));
        const QString tunnelName = tunnelLoad.value(QStringLiteral("tunnelName")).toString();
        const QString physName = tunnelLoad.value(QStringLiteral("physicalName")).toString();
        if (tunnelFound) {
            section.findings.push_back(makeFinding(section.id,
                                                   QStringLiteral("Пропускная способность VPN-интерфейса"),
                                                   QStringLiteral("%1: %2 Mbps out, %3 Mbps in")
                                                       .arg(tunnelName.isEmpty() ? QStringLiteral("tunnel") : tunnelName,
                                                            QString::number(tunOut, 'f', 2),
                                                            QString::number(tunIn, 'f', 2)),
                                                   DiagnosticStatus::Info));
            const bool heavyUp = tunOut > 4.0;
            const bool heavyDown = tunIn > 20.0;
            if (heavyUp || heavyDown) {
                section.findings.push_back(makeFinding(section.id,
                                                       QStringLiteral("VPN-трафик нагружает канал"),
                                                       QStringLiteral("Через туннель %1 Mbps out / %2 Mbps in. Делит очередь с игровым трафиком.")
                                                           .arg(QString::number(tunOut, 'f', 2), QString::number(tunIn, 'f', 2)),
                                                       DiagnosticStatus::Warning,
                                                       QStringLiteral("Поставьте на паузу загрузки/стримы в tunneled-процессах.")));
            }
        }
        if (physOut > 0.0 || physIn > 0.0) {
            section.findings.push_back(makeFinding(section.id,
                                                   QStringLiteral("Суммарная пропускная способность физического адаптера"),
                                                   QStringLiteral("%1: %2 Mbps out, %3 Mbps in")
                                                       .arg(physName.isEmpty() ? QStringLiteral("physical") : physName,
                                                            QString::number(physOut, 'f', 2),
                                                            QString::number(physIn, 'f', 2)),
                                                   DiagnosticStatus::Info));
        }
    }

    if (!t.isEmpty() && !aTunneled.isEmpty()) {
        const double rttTarget = mapNumber(t, QStringLiteral("rttMs"));
        const double rttTunneled = mapNumber(aTunneled, QStringLiteral("rttMs"));
        if (rttTarget > 0.0 && rttTunneled > 0.0) {
            const double rttGameDelta = rttTarget - rttTunneled;
            section.findings.push_back(makeFinding(
                section.id,
                QStringLiteral("Расстояние до игрового сервера через VPN"),
                QStringLiteral("Tunneled anchor %1 ms -> Game %2 ms (дельта +%3 ms)")
                    .arg(QString::number(rttTunneled, 'f', 1),
                         QString::number(rttTarget, 'f', 1),
                         QString::number(rttGameDelta, 'f', 1)),
                DiagnosticStatus::Info));
        }
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

DiagnosticSection DiagnosticRuleEngine::evaluateGameServer(const QHash<QString, QVariantMap>& snapshots, const ConnectionInfo* ci) const {
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
                                               QStringLiteral("Игровой поток не измеряется"),
                                               QStringLiteral("UDP-проба до игрового сервера недоступна"),
                                               DiagnosticStatus::Info,
                                               QStringLiteral("Убедитесь, что выбран активный игровой поток с реальным remote IP.")));
        return section;
    }
    if (!t.isEmpty()) {
        const double rtt = mapNumber(t, QStringLiteral("rttMs"), -1.0);
        const double jitter = mapNumber(t, QStringLiteral("jitterMs"));
        const double a2sLoss = mapNumber(t, QStringLiteral("lossPercent"));
        const double a2sSamples = mapNumber(t, QStringLiteral("samples"), 0.0);
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
            section.findings.push_back(makeFinding(section.id,
                                                   QStringLiteral("RTT сервера"),
                                                   QStringLiteral("RTT: %1 ms").arg(QString::number(rtt, 'f', 1)),
                                                   rttStatus));
            if (ci != nullptr && ci->routedThroughKind == InterfaceKind::VpnTunnel && rtt < 5.0) {
                section.findings.push_back(makeFinding(section.id,
                                                       QStringLiteral("Подозрительный RTT через VPN"),
                                                       QStringLiteral("RTT %1 ms выглядит неестественно для удаленного сервера").arg(QString::number(rtt, 'f', 1)),
                                                       DiagnosticStatus::Warning,
                                                       QStringLiteral("Дождитесь UDP-пробы/полной диагностики для подтверждения.")));
            }
        }
        if (jitter > 30.0) {
            section.findings.push_back(makeFinding(section.id, QStringLiteral("Высокий джиттер"), QStringLiteral("Джиттер: %1 ms").arg(QString::number(jitter, 'f', 1)), DiagnosticStatus::Problem));
        }
        if (a2sSamples > 0.0) {
            if (a2sLoss > 30.0) {
                section.findings.push_back(makeFinding(section.id,
                                                       QStringLiteral("A2S query response rate низкий"),
                                                       QStringLiteral("A2S loss: %1% (%2 проб) — может быть policy сервера, не сетевые потери")
                                                           .arg(QString::number(a2sLoss, 'f', 1), QString::number(a2sSamples, 'f', 0)),
                                                       DiagnosticStatus::Info,
                                                       QStringLiteral("Source 2 сервер выборочно отвечает на A2S; сверяйте с in-game net_graph 3.")));
            } else if (a2sLoss > 1.0) {
                section.findings.push_back(makeFinding(section.id,
                                                       QStringLiteral("A2S loss"),
                                                       QStringLiteral("Потери A2S: %1%").arg(QString::number(a2sLoss, 'f', 1)),
                                                       DiagnosticStatus::Problem,
                                                       QStringLiteral("Сверяйте с in-game net_graph 3; A2S может завышать loss.")));
            } else {
                section.findings.push_back(makeFinding(section.id,
                                                       QStringLiteral("A2S loss"),
                                                       QStringLiteral("Потери A2S: %1%").arg(QString::number(a2sLoss, 'f', 1)),
                                                       DiagnosticStatus::Ok));
            }
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
    const double target = mapNumber(bg, QStringLiteral("targetProcessMbps"));
    const double tunnel = mapNumber(bg, QStringLiteral("tunnelMbps"));
    const double threshold = mapNumber(bg, QStringLiteral("warningThresholdMbps"), 20.0);
    const auto talkers = bg.value(QStringLiteral("topTalkers")).toList();
    QString topText;
    if (!talkers.isEmpty()) {
        const auto top = talkers.first().toMap();
        topText = QStringLiteral(" Топ: %1 (%2 Mbps)")
                      .arg(top.value(QStringLiteral("process")).toString(),
                           QString::number(top.value(QStringLiteral("bandwidthMbps")).toDouble(), 'f', 1));
    }
    section.findings.push_back(makeFinding(section.id, QStringLiteral("Игровой процесс"), QStringLiteral("%1 Mbps").arg(QString::number(target, 'f', 1)), DiagnosticStatus::Info));
    section.findings.push_back(makeFinding(section.id, QStringLiteral("Тоннельные процессы"), QStringLiteral("%1 Mbps").arg(QString::number(tunnel, 'f', 1)), DiagnosticStatus::Info));
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
