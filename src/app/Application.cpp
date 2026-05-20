#include "app/Application.h"

#include "platform/windows/WinapiUtils.h"
#include "ui/MainWindow.h"

#include <QMessageBox>
#include <QPalette>
#include <QColor>
#include <QStringList>
#include <QStyleFactory>

namespace gpd::app {

Application::Application(int& argc, char** argv)
    : QApplication(argc, argv) {
    setApplicationName(QStringLiteral("RouteLens"));
    setApplicationDisplayName(tr("RouteLens"));
    setOrganizationName(QStringLiteral("RouteLens"));
    setApplicationVersion(QStringLiteral("0.1.0"));

    smokeTest_ = arguments().contains(QStringLiteral("--smoke-test"));
    applyTheme();
}

bool Application::isSmokeTest() const noexcept {
    return smokeTest_;
}

int Application::run() {
    if (smokeTest_) {
        return 0;
    }

    showPrivilegeWarningIfNeeded();

    gpd::ui::MainWindow window;
    window.show();
    return exec();
}

void Application::applyTheme() {
    setStyle(QStyleFactory::create(QStringLiteral("Fusion")));

    QPalette palette;
    palette.setColor(QPalette::Window, QColor(30, 33, 39));
    palette.setColor(QPalette::WindowText, QColor(230, 234, 241));
    palette.setColor(QPalette::Base, QColor(21, 24, 29));
    palette.setColor(QPalette::AlternateBase, QColor(38, 42, 49));
    palette.setColor(QPalette::ToolTipBase, QColor(230, 234, 241));
    palette.setColor(QPalette::ToolTipText, QColor(21, 24, 29));
    palette.setColor(QPalette::Text, QColor(230, 234, 241));
    palette.setColor(QPalette::Button, QColor(44, 49, 58));
    palette.setColor(QPalette::ButtonText, QColor(230, 234, 241));
    palette.setColor(QPalette::BrightText, Qt::red);
    palette.setColor(QPalette::Highlight, QColor(67, 133, 255));
    palette.setColor(QPalette::HighlightedText, Qt::white);
    setPalette(palette);
}

void Application::showPrivilegeWarningIfNeeded() {
    if (gpd::platform::isRunningAsAdministrator()) {
        return;
    }

    QMessageBox::warning(
        nullptr,
        tr("Administrator privileges required"),
        tr("RouteLens needs administrator privileges for ICMP diagnostics and full connection table access. Restart the application as administrator."));
}

} // namespace gpd::app
