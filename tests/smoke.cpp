#include "core/Models.h"

int main() {
    return gpd::core::routeVerdictToString(gpd::core::RouteVerdict::Direct) == QStringLiteral("DIRECT") ? 0 : 1;
}
