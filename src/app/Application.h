#pragma once

#include <QApplication>

namespace gpd::app {

class Application final : public QApplication {
public:
    Application(int& argc, char** argv);
    ~Application() override;

    [[nodiscard]] bool isSmokeTest() const noexcept;
    [[nodiscard]] int run();

private:
    void applyTheme();
    void showPrivilegeWarningIfNeeded();

    bool smokeTest_{false};
};

} // namespace gpd::app
