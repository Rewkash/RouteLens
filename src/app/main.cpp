#include "app/Application.h"
#include "app/Logger.h"

int main(int argc, char* argv[]) {
    gpd::app::Application application(argc, argv);
    gpd::app::installMessageLogger();
    return application.run();
}
