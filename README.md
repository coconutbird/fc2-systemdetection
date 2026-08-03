# fc2-systemdetection

[![CI](https://github.com/coconutbird/fc2-systemdetection/actions/workflows/ci.yml/badge.svg)](https://github.com/coconutbird/fc2-systemdetection/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/coconutbird/fc2-systemdetection)](https://github.com/coconutbird/fc2-systemdetection/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A 32-bit drop-in replacement for Far Cry 2's `systemdetection.dll`. It
supports high-core-count systems and applies a small set of validated runtime
patches to `Dunia.dll`.

## Features

CPU detection supports systems with 32 or more logical processors.

Runtime patches are resolved inside
[Portex](https://github.com/coconutbird/portex)-parsed PE sections. Every
signature-relative destination must be unique and contain either the exact
expected game bytes or the exact patched bytes before anything is written.

| Patch | Default | Behavior |
| --- | --- | --- |
| `jackal_tapes` | On | Fixes incorrect Southern-map Jackal tape recordings |
| `devmode_always_on` | On | Permanently bypasses the developer-command visibility check |
| `predecessor_tapes` | On | Unlocks the seven predecessor bonus missions |
| `machetes` | On | Unlocks the two bonus machete skins |
| `no_blinking_items` | Off | Disables three interactable/objective blinking effects |

Steam, Retail/GOG, and Ubisoft Connect 1.03 file layouts are recognized. An
unknown build is never patched from an unguarded address: compatible
signature-based patches may resolve, while unsupported targets fail closed
and are reported.

## Installation

1. Download `systemdetection.dll` from
   [Releases](https://github.com/coconutbird/fc2-systemdetection/releases).
2. Back up the existing `bin/systemdetection.dll`.
3. Copy the downloaded DLL into the game's `bin` directory.
4. Launch the game.

Common installation locations include:

- Steam: `C:\Program Files (x86)\Steam\steamapps\common\Far Cry 2\bin`
- GOG: `C:\GOG Games\Far Cry 2\bin`
- Ubisoft Connect:
  `C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\games\Far Cry 2\bin`

## Optional configuration

No configuration file is required. To change patch defaults, copy
[`fc2-systemdetection.ini.example`](fc2-systemdetection.ini.example) beside
the DLL and rename it to `fc2-systemdetection.ini`.

```ini
[patches]
jackal_tapes = true
devmode_always_on = true
predecessor_tapes = true
machetes = true
no_blinking_items = false
```

Values may be `true`/`false`, `yes`/`no`, `on`/`off`, or `1`/`0`. Disabled
patches are not scanned.

On initialization, the DLL writes `fc2-systemdetection.log` beside itself.
The log records build detection, configuration warnings, and whether every
patch was applied, already applied, disabled, or rejected.

## Building

Install [rustup](https://rustup.rs/), then run the normal Cargo commands from
the repository root:

```powershell
cargo test
cargo build --release
```

`rust-toolchain.toml` selects nightly and provisions Clippy, rustfmt, and the
32-bit MSVC standard library. `.cargo/config.toml` selects
`i686-pc-windows-msvc` as the default build target.

The DLL is written to
`target/i686-pc-windows-msvc/release/systemdetection.dll`.

## Development checks

[prek](https://prek.j178.dev/) manages the repository's commit checks. If you
use [mise](https://mise.jdx.dev/), the checked-in `mise.toml` tracks the latest
Rust and prek releases:

```powershell
mise install
prek install
```

Otherwise, install prek using its normal package for your platform, then run
`prek install`. The hook runs rustfmt, Clippy with warnings denied, and the
test suite using the repository-selected Rust toolchain. It also checks line
endings, whitespace, merge markers, and TOML/YAML syntax. Run the same checks
across the worktree on demand with:

```powershell
prek run --all-files
```

To validate a legally obtained `Dunia.dll` without launching the game, point
the ignored integration test at it:

```powershell
$env:FC2_DUNIA_DLL = "C:\path\to\Dunia.dll"
cargo test --test dunia-validation -- --ignored --nocapture
```

The test parses the file with Portex, reconstructs its sections in disposable
heap memory, checks the real patch plans and known RVAs, and applies each patch
twice to that copy to verify idempotency. It never loads or executes the game
DLL.

## License

[MIT](LICENSE)
