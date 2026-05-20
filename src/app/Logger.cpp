#include "app/Logger.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QMutex>
#include <QStandardPaths>
#include <QTextStream>
#include <QtLogging>

namespace {

QMutex g_logMutex;
QFile g_logFile;

QString logDirectoryPath() {
    const auto base = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    return QDir(base).filePath(QStringLiteral("logs"));
}

void messageHandler(QtMsgType type, const QMessageLogContext& context, const QString& message) {
    QMutexLocker locker(&g_logMutex);
    if (!g_logFile.isOpen()) {
        return;
    }

    const auto typeText = [type]() -> QString {
        switch (type) {
        case QtDebugMsg:
            return QStringLiteral("DEBUG");
        case QtInfoMsg:
            return QStringLiteral("INFO");
        case QtWarningMsg:
            return QStringLiteral("WARN");
        case QtCriticalMsg:
            return QStringLiteral("ERROR");
        case QtFatalMsg:
            return QStringLiteral("FATAL");
        }
        return QStringLiteral("UNKNOWN");
    }();

    QTextStream stream(&g_logFile);
    stream << QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs) << ' ' << typeText << ' ' << message;
    if (context.file != nullptr) {
        stream << " (" << context.file << ':' << context.line << ')';
    }
    stream << Qt::endl;

    if (type == QtFatalMsg) {
        abort();
    }
}

} // namespace

namespace gpd::app {

void installMessageLogger() {
    const QDir logDir(logDirectoryPath());
    if (!logDir.exists()) {
        QDir().mkpath(logDir.absolutePath());
    }

    g_logFile.setFileName(logDir.filePath(QStringLiteral("app.log")));
    if (!g_logFile.open(QIODevice::Append | QIODevice::Text)) {
        return;
    }
    qInstallMessageHandler(messageHandler);
}

} // namespace gpd::app
