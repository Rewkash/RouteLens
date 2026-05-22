#pragma once

#include "core/ClashApiClient.h"
#include "core/Models.h"

#include <QHash>

#include <optional>

namespace gpd::core {

class ClashConnectionMatcher final {
public:
    struct Match {
        QString outboundName;
        QVector<QString> chains;
        QString rule;
        QString rulePayload;
        QString clashId;
    };

    void rebuildIndex(const ClashApiSnapshot& snapshot);
    [[nodiscard]] std::optional<Match> findFor(const ConnectionInfo& conn) const;

private:
    QHash<QString, ClashConnection> byProcessDestKey_;
    QHash<QString, ClashConnection> byDestKey_;
};

} // namespace gpd::core
