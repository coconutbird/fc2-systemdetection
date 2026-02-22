# fc2-systemdetection

[![CI](https://github.com/coconutbird/fc2-systemdetection/actions/workflows/ci.yml/badge.svg)](https://github.com/coconutbird/fc2-systemdetection/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/coconutbird/fc2-systemdetection)](https://github.com/coconutbird/fc2-systemdetection/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Drop-in replacement for Far Cry 2's `systemdetection.dll`.

## Why?

The original DLL crashes on systems with 32+ logical CPU cores due to a bug in the CPU topology detection code. This replacement fixes that issue.

## Installation

1. Download `systemdetection.dll` from [Releases](https://github.com/coconutbird/fc2-systemdetection/releases)
2. Navigate to your Far Cry 2 installation folder
3. Backup the original `bin/systemdetection.dll`
4. Copy the downloaded DLL to the `bin` folder
5. Launch the game

### Common Install Locations

- **Steam**: `C:\Program Files (x86)\Steam\steamapps\common\Far Cry 2\bin`
- **GOG**: `C:\GOG Games\Far Cry 2\bin`
- **Ubisoft Connect**: `C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\games\Far Cry 2\bin`

## Building

Requires Rust nightly and the 32-bit MSVC toolchain:

```
rustup target add i686-pc-windows-msvc
cargo build --release
```

The DLL will be at `target/i686-pc-windows-msvc/release/systemdetection.dll`

## License

[MIT](LICENSE)
