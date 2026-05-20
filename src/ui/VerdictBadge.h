#pragma once

#include "core/Models.h"

#include <QLabel>

namespace gpd::ui {

class VerdictBadge final : public QLabel {
    Q_OBJECT

public:
    explicit VerdictBadge(QWidget* parent = nullptr);

    void setVerdict(const gpd::core::VerdictSummary& summary);
};

} // namespace gpd::ui
