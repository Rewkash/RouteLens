# Build Guide

## Toolchain

- Visual Studio 2022, x64 MSVC toolchain.
- CMake 3.21+.
- Ninja.
- vcpkg in manifest mode.

## Bootstrap vcpkg

```powershell
git clone https://github.com/microsoft/vcpkg.git C:\dev\vcpkg
C:\dev\vcpkg\bootstrap-vcpkg.bat
$env:VCPKG_ROOT = "C:\dev\vcpkg"
```

## Configure

Run from a Visual Studio Developer PowerShell or a shell where MSVC is available:

```powershell
cmake --preset windows-msvc-debug
```

The preset uses `VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake` and installs dependencies declared in `vcpkg.json`.

## Configure With Existing Qt Install

If you already have a working Qt installation, use the same pattern as the existing local projects and point CMake at Qt directly:

```powershell
cmake --preset windows-vs2026-qt-local
cmake --build --preset windows-vs2026-qt-local-release
ctest --preset windows-vs2026-qt-local-release
```

The checked local preset matches the existing working environment: `Visual Studio 18 2026` and `I:/Qt/6.10.2/msvc2022_64`. This mode does not require `VCPKG_ROOT`.

## Build

```powershell
cmake --build --preset windows-msvc-debug --config Debug
```

## Smoke Test

```powershell
ctest --test-dir build/windows-msvc-debug --output-on-failure -C Debug
```

The smoke test builds and runs a separate non-elevated test target. The main GUI executable still embeds `requireAdministrator`, so it should be launched manually for UI checks.

## Formatting

```powershell
clang-format -i src\app\*.cpp src\app\*.h src\core\*.h src\platform\windows\*.cpp src\platform\windows\*.h src\ui\*.cpp src\ui\*.h
```

## Packaging

Packaging is planned for Milestone 7 with `windeployqt` and Inno Setup.
