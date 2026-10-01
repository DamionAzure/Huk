# Huk

**Automatically creates global shims for developer tools installed in isolated environments.**

`huk` is a small Windows CLI that collects executables from separate toolchain directories (MSYS2, LLVM, MSVC, cargo, Go, etc.) into one shim directory, `~/.huk/shims`, and prefixes each one with a namespace. You put that single folder on your `PATH` instead of dumping every toolchain's `bin` directory onto it.

Because every tool is namespaced, same-named tools from different toolchains never collide:

```
ucrt-gcc      mingw-gcc      clang64-gcc
ucrt-make     mingw-make     cargo-rustc
```

## Why

Putting `C:\msys64\ucrt64\bin`, `C:\msys64\mingw64\bin`, LLVM, and others on `PATH` all at once means whichever comes first wins, and you often end up with the wrong `gcc`, `ld`, or `python`. With `huk`, you choose the toolchain explicitly by name (`ucrt-gcc` vs `mingw-gcc`), and nothing else leaks into your `PATH`.

## How it works

For each executable found in a directory, `huk` writes two small shim files into `~/.huk/shims`:

| Shim | Used from |
|---|---|
| `<namespace>-<name>.cmd` | CMD / PowerShell |
| `<namespace>-<name>` (no extension) | Git Bash / MSYS2 / other `sh` shells |

Each shim prepends the toolchain's directory to `PATH` for the duration of the call, so tools that load sibling DLLs or call other binaries from their own toolchain keep working. Supported source files:

- `.exe`: invoked directly
- `.bat` / `.cmd`: invoked via `call` (CMD) or `cmd.exe` (shell)
- `.ps1`: invoked via `powershell -NoProfile -ExecutionPolicy Bypass -File`

The registry of what is hooked lives in `~/.huk/config.json`, with a rotating backup at `config.json.bak`.

## Installation

Requires a recent Rust toolchain (the crate uses the 2024 edition, so Rust 1.85 or newer).

```powershell
git clone https://github.com/DamionAzure/Huk.git huk
cd huk
cargo build --release
```

Copy `target\release\huk.exe` somewhere permanent on your `PATH`, then let `huk` add its shim directory to your User `PATH`:

```powershell
huk doctor --fix
```

Restart your terminal afterwards so the new `PATH` takes effect.

## Quick start

```powershell
# See which common toolchains are installed and not yet hooked
huk scan

# ...or hook them interactively
huk scan -i

# Or hook a directory yourself under a namespace of your choice
huk add ucrt C:\msys64\ucrt64\bin

# Preview first without writing anything
huk add ucrt C:\msys64\ucrt64\bin --dry-run

# Use it
ucrt-gcc --version
```

## Commands

| Command | Description |
|---|---|
| `huk scan [-i]` | Look for common toolchains (MSYS2 UCRT64/MinGW64/Clang64, LLVM, MSVC, cargo, Go). With `-i`, prompt to hook each one. |
| `huk add <namespace> <path> [-n]` | Hook every `.exe`/`.bat`/`.cmd`/`.ps1` in `<path>` under `<namespace>`. `-n` / `--dry-run` shows what would happen. Re-running on an existing namespace refreshes it. |
| `huk list` | List all registered namespaces with binary and alias counts. |
| `huk info <namespace>` | Show the source path and every binary and alias in a namespace. |
| `huk find <name>` | Case-insensitive substring search across all namespaces, e.g. `huk find gcc`. |
| `huk alias <namespace> <binary> <alias>` | Create an extra name for an already-hooked binary (e.g. `ucrt-gcc` → `ucrt-cc`). |
| `huk delete <namespace> [binary] [-y]` | Remove one binary or alias, or the whole namespace if `binary` is omitted or `all`. Removing a binary also removes aliases pointing at it. |
| `huk doctor [--fix]` | Health check; with `--fix`, repair what it can. |
| `huk clean [-y]` | Remove namespaces whose source directory is gone or that have zero binaries. |
| `huk uninstall [-y]` | Remove all namespaces, all shim files, and `config.json`. |
| `huk completions <shell>` | Print a shell completion script (`powershell`, `bash`, `zsh`, `fish`, ...). |

Run `huk <command> --help` for full details on any command.

### Aliases

Some tools look for a specific name. Alias one of your hooked binaries to it:

```powershell
huk info ucrt                  # find the exact name
huk alias ucrt gcc cc          # creates ucrt-cc as a copy of ucrt-gcc
```

Aliases are copies of the shims, not symlinks. When you re-run `huk add` on a namespace, an alias is kept as long as its source binary still exists on disk.

### Doctor

`huk doctor` checks that:

1. `~/.huk/shims` is on your `PATH`
2. `config.json` exists and parses
3. every registered binary and alias still has its shim files
4. there are no untracked ("orphan") files in the shim directory
5. no names collide when compared case-insensitively (Windows is case-insensitive, so `Tool` and `tool` would share a file)

With `--fix`, it will add the shim directory to your User `PATH`, restore `config.json` from its backup if corrupt, regenerate missing shims where the source directory is still reachable, and delete orphan files. Case collisions are only reported, since `huk` can't know which one you want to keep.

### Shell completions

```powershell
# PowerShell: add to your $PROFILE
huk completions powershell | Out-String | Invoke-Expression
```

```bash
# Bash
huk completions bash > ~/.local/share/bash-completion/completions/huk
```

## Safety notes

- If `config.json` exists but can't be parsed, `huk` refuses to run any command except `doctor`, so it never overwrites your real data with an empty config.
- Namespace and alias names are validated: no empty names, `.`/`..`, control characters, or characters Windows forbids in filenames (`< > : " / \ | ? *`).
- `huk uninstall` clears the whole shim directory. It does **not** delete `huk.exe` itself or remove `~/.huk/shims` from your `PATH`; do those by hand if you're fully removing it.

## Building and testing

```powershell
cargo build
cargo test
```

## Platform

Windows. Paths, shim formats, and the `PATH` handling in `doctor --fix` (which calls PowerShell) are Windows-specific.

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.