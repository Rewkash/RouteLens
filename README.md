# RouteLens

Windows desktop diagnostic tool for game network routes and latency. It is a transparent analyzer, not a VPN, accelerator, packet modifier, or traffic shaper.

Current status: Milestone 1 scaffold.

## Features In This Milestone

- Qt 6 Widgets application shell with dark Fusion theme.
- Windows-only CMake project targeting C++20.
- Administrator manifest for future ICMP and connection-table diagnostics.
- Basic logging to `%APPDATA%/RouteLens/logs/app.log`.
- CI workflow for Windows build and smoke test target.
- Initial architecture directories for `app`, `core`, `platform/windows`, and `ui`.

## Planned Milestones

1. Project scaffold and CI.
2. Process list and TCP/UDP connection scanner.
3. ICMP ping probes, jitter/loss calculation, and charts.
4. Traceroute and GeoIP lookup.
5. Interface inspection and Direct/VPN/Split classifier.
6. SQLite session recording and comparison.
7. Localization, packaging, installer, and polish.

## Requirements

- Windows 10/11 x64.
- Visual Studio 2022 with C++ workload.
- CMake 3.21 or newer.
- Ninja.
- vcpkg.

## Build

```powershell
$env:VCPKG_ROOT = "C:\path\to\vcpkg"
cmake --preset windows-msvc-release
cmake --build --preset windows-msvc-release --config Release
ctest --test-dir build/windows-msvc-release --output-on-failure -C Release
```

If Qt is already installed and visible to CMake, the project can also be configured without vcpkg:

```powershell
cmake --preset windows-vs2026-qt-local
cmake --build --preset windows-vs2026-qt-local-release
ctest --preset windows-vs2026-qt-local-release
```

See `BUILD.md` for detailed setup.

## Run

```powershell
build\windows-msvc-release\RouteLens.exe
```

Windows will request elevation because the executable embeds `requireAdministrator`.

## Security Model

- Read-only diagnostics only.
- No route, firewall, DNS, hosts, or adapter modifications.
- No telemetry.
- No packet modification or process injection.

## License

MIT. See `LICENSE`.
