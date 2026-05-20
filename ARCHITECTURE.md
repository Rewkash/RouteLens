# Architecture

## Layers

`src/app` contains application bootstrap, dependency wiring, process lifetime, theme setup, and logging.

`src/core` contains business models and, in later milestones, diagnostics logic. It must not depend on Qt Widgets or WinAPI headers.

`src/platform/windows` contains all Windows API boundaries. Any future includes of `windows.h`, `iphlpapi.h`, `icmpapi.h`, `tlhelp32.h`, or similar headers belong here.

`src/ui` contains Qt Widgets views and presentation components. It must not call WinAPI directly.

## Current Milestone Flow

`main.cpp` creates `gpd::app::Application`, installs the Qt message logger, applies the default theme, checks smoke-test mode, and shows `MainWindow`.

`MainWindow` currently renders a disabled process selector, disabled monitoring controls, the verdict badge, and the empty connection table expected by the target UI.

## Future Data Flow

1. UI selects a process ID.
2. Core services poll process connections and emit model updates through Qt signals.
3. Platform services provide Windows-specific snapshots for connections, adapters, routes, ICMP, and traceroute.
4. Core classifiers produce Direct/VPN/Split verdicts.
5. UI renders connection rows, charts, traceroute hops, and interface state.
6. Session recorder persists snapshots to SQLite for comparison.

## Threading

Long operations must run outside the UI thread using `QThread` or `QtConcurrent::run`. UI updates must return to the main thread through queued Qt signals.

## Dependency Rules

- `ui` can depend on `core` models.
- `core` can depend on QtCore, but not QtWidgets.
- `platform/windows` can depend on WinAPI and QtCore conversion helpers.
- `core` should consume platform abstractions instead of including Windows headers.
