use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Debug, Default)]
struct Config {
    hooks: HashMap<String, HookEntry>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct HookEntry {
    path: PathBuf,
    /// Real binaries discovered on disk (one shim pair per entry).
    binaries: Vec<String>,
    /// Aliases created with `huk alias`: alias name -> source binary name.
    /// Kept separate from `binaries` so list/info can distinguish real
    /// hooked executables from copies of them.
    #[serde(default)]
    aliases: HashMap<String, String>,
}

/// The kind of executable a source file is, which determines how its shims
/// are written (a plain .exe is invoked directly; .bat/.cmd need `call`;
/// .ps1 needs to go through powershell.exe).
#[derive(Clone, Copy)]
enum SourceKind {
    Exe,
    BatCmd,
    Ps1,
}

fn classify(path: &Path) -> Option<SourceKind> {
    let ext = path.extension()?.to_str()?.to_lowercase();
    match ext.as_str() {
        "exe" => Some(SourceKind::Exe),
        "bat" | "cmd" => Some(SourceKind::BatCmd),
        "ps1" => Some(SourceKind::Ps1),
        _ => None,
    }
}

fn to_posix(p: &Path) -> String {
    p.display().to_string().replace('\\', "/")
}

/// Characters that are invalid in a Windows filename. A namespace or alias name
/// becomes part of a shim filename (`namespace-binary[.cmd]`), so anything on this
/// list would either fail to write or silently corrupt an adjacent shim.
const RESERVED_FILENAME_CHARS: &[char] = &['<', '>', ':', '"', '/', '\\', '|', '?', '*'];

/// Rejects names that would produce an invalid or dangerous filename on Windows:
/// reserved characters, control characters, empty names, and "." / "..".
fn validate_name(kind: &str, name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err(format!("{} cannot be empty", kind));
    }
    if name == "." || name == ".." {
        return Err(format!("{} cannot be '.' or '..'", kind));
    }
    if let Some(c) = name.chars().find(|c| RESERVED_FILENAME_CHARS.contains(c) || c.is_control()) {
        return Err(format!(
            "{} contains invalid character '{}' (reserved on Windows: < > : \" / \\ | ? *)",
            kind, c
        ));
    }
    Ok(())
}

/// Windows filesystems are case-insensitive, so two namespaces (or two binaries
/// within one namespace) differing only by case would collide on the same shim
/// files on disk even though Huk's config.json treats them as distinct entries.
/// Returns the existing key that collides with `name`, if any (excluding an exact
/// match, which is a legitimate re-add rather than a collision).
fn find_case_conflict<'a, I: Iterator<Item = &'a String>>(keys: I, name: &str) -> Option<&'a String> {
    keys.into_iter().find(|k| k.eq_ignore_ascii_case(name) && k.as_str() != name)
}

#[derive(Parser)]
#[command(
    name = "huk",
    about = "Hooks your isolated toolchains together.",
    long_about = "Huk hooks binaries from isolated toolchain directories (MSYS2, MSVC, cargo, go, etc.) \
into a single shim directory (~/.huk/shims), namespacing each one (e.g. `ucrt-gcc`) so \
tools with the same name from different toolchains never collide on PATH. Supports .exe, \
.bat, .cmd, and .ps1 source files."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan common toolchain install locations for unhooked binaries
    #[command(long_about = "Scans well-known toolchain locations (MSYS2 UCRT/MinGW/Clang64, LLVM, MSVC, cargo, go) \
for directories containing executables that aren't hooked yet. Run without flags to just \
list what it finds, or with --interactive to be prompted to hook each one on the spot.")]
    Scan {
        /// Prompt to hook each discovered toolchain instead of just listing them
        #[arg(short, long)]
        interactive: bool,
    },

    /// Hook every .exe/.bat/.cmd/.ps1 in a directory under a namespace
    #[command(long_about = "Scans PATH for every .exe, .bat, .cmd, and .ps1 file, creates a CMD (.cmd) and a POSIX \
shell shim for each one in ~/.huk/shims, prefixed with NAMESPACE- (e.g. `cargo-rustc.exe`), \
and records the mapping in config.json. Re-running Add on an existing namespace carries \
forward any aliases whose source binary still exists (recreating their shim files if those \
happened to go missing), and unhooks (with a notice) anything that's no longer on disk.")]
    Add {
        /// Short name used to prefix every shim created from this directory (e.g. "ucrt", "cargo")
        namespace: String,
        /// Directory to scan for executables
        path: PathBuf,
        /// Show what would be hooked without writing any shims or touching config.json
        #[arg(short = 'n', long)]
        dry_run: bool,
    },

    /// Remove one binary's shims, or an entire namespace
    #[command(long_about = "Deletes the CMD and shell shims for BINARY under TARGET namespace and removes it from \
config.json. Omit BINARY (or pass \"all\") to unhook every binary and alias in the namespace \
and remove the namespace entirely. Deleting a real binary also removes any aliases pointing \
at it.")]
    Delete {
        /// Namespace to delete from (see `huk list`)
        target: String,
        /// Specific binary or alias name to unhook, or "all" to remove the whole namespace
        #[arg(default_value = "all")]
        binary: String,
        /// Skip the confirmation prompt (only asked when removing an entire namespace)
        #[arg(short, long)]
        yes: bool,
    },

    /// List every registered namespace and how many binaries/aliases each has
    List,

    /// Search for a binary or alias by name across every registered namespace
    #[command(long_about = "Searches every registered namespace for a binary or alias matching NAME (substring, \
case-insensitive) and prints the full shim name for each match, so you don't have to \
remember or guess which namespace a tool lives under.")]
    Find {
        /// Name (or partial name) to search for, e.g. "gcc"
        name: String,
    },

    /// Check shim health: PATH, config.json validity, missing shims, and orphaned files
    #[command(long_about = "Runs a full health check: confirms ~/.huk/shims is on PATH, confirms config.json parses, \
confirms every registered binary and alias still has its CMD and shell shim files on disk, \
and flags any shim files present in ~/.huk/shims that aren't tracked in config.json at all. \
Pass --fix to attempt automatic repair: persist ~/.huk/shims onto your User PATH, restore \
config.json from its last backup if it's corrupt, regenerate missing shims for namespaces \
whose source directory is still reachable, and delete untracked orphan shim files.")]
    Doctor {
        /// Attempt to automatically repair any issues found
        #[arg(short, long)]
        fix: bool,
    },

    /// Remove namespaces whose source directory is gone or that have zero binaries
    #[command(long_about = "Finds namespaces whose source path no longer exists, or that have zero binaries \
registered, and removes them (and their shim files, including aliases) from config.json. \
Prompts for confirmation before deleting unless --yes is given.")]
    Clean {
        /// Skip the confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },

    /// Show every binary and alias hooked under a namespace
    #[command(long_about = "Prints the source path and the full list of shim names registered under NAMESPACE, \
with real binaries and aliases (created via `huk alias`) shown in separate sections.")]
    Info {
        /// Namespace to inspect (see `huk list`)
        namespace: String,
    },

    /// Create an extra shim name pointing at an already-hooked binary
    #[command(long_about = "Copies the existing CMD and shell shims for NAMESPACE-BINARY to a new name, \
NAMESPACE-ALIAS, and registers ALIAS as an alias under NAMESPACE. Useful when a tool expects \
a specific binary name (e.g. aliasing `gcc` to `cc`). BINARY must already be hooked as a real \
binary; use `huk info NAMESPACE` to see exact names. Aliases are copies, not symlinks: \
re-running `huk add` will keep an alias only as long as its source binary still exists.")]
    Alias {
        /// Namespace the source binary is registered under
        namespace: String,
        /// Existing binary name to alias, exactly as shown by `huk info`
        binary: String,
        /// New name to create as a copy of BINARY
        alias: String,
    },

    /// Remove every namespace, all shim files, and config.json
    #[command(long_about = "Unhooks every namespace and deletes every shim file in ~/.huk/shims, along with \
config.json and its backup. Does NOT delete the huk.exe binary itself or ~/.huk/shims from \
your PATH - remove those manually if you're fully uninstalling.")]
    Uninstall {
        /// Skip the confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },

    /// Generate a shell completion script for the given shell
    Completions {
        /// Target shell (e.g. powershell, bash, zsh, fish)
        #[arg(value_enum)]
        shell: Shell,
    },
}

fn main() {
    let cli = Cli::parse();

    // Intercept completions early before checking files or directories
    if let Commands::Completions { shell } = cli.command {
        let mut cmd = Cli::command();
        let bin_name = cmd.get_name().to_string();
        generate(shell, &mut cmd, bin_name, &mut io::stdout());
        return;
    }

    let home_dir = match dirs::home_dir() {
        Some(d) => d,
        None => {
            eprintln!("[!] Could not determine your home directory. Huk cannot continue.");
            std::process::exit(1);
        }
    };
    let huk_dir = home_dir.join(".huk");
    let shim_dir = huk_dir.join("shims");
    let config_path = huk_dir.join("config.json");

    fs::create_dir_all(&shim_dir).ok();

    let (mut config, config_broken): (Config, bool) = if config_path.exists() {
        match fs::read_to_string(&config_path) {
            Ok(content) => match serde_json::from_str::<Config>(&content) {
                Ok(c) => (c, false),
                Err(_) => (Config::default(), true),
            },
            Err(_) => (Config::default(), true),
        }
    } else {
        (Config::default(), false)
    };

    // If config.json is present but unreadable/corrupt, refuse to proceed for anything
    // that might save over it with an empty config - that would destroy the real data.
    // `doctor` is exempt since it's the tool for diagnosing and fixing exactly this.
    if config_broken && !matches!(cli.command, Commands::Doctor { .. }) {
        eprintln!("[!] config.json exists but could not be read or parsed. Refusing to continue, to avoid overwriting it with empty data.");
        eprintln!("    Run 'huk doctor' to see details, or 'huk doctor --fix' to attempt automatic recovery from the last backup.");
        std::process::exit(1);
    }

    if !config_broken {
        migrate_legacy_aliases(&mut config, &config_path);
    }

    match &cli.command {
        Commands::Add { namespace, path, dry_run } => {
            if !path.exists() {
                eprintln!("[!] Error: Path does not exist: {}", path.display());
                return;
            }
            if let Err(e) = validate_name("namespace", namespace) {
                eprintln!("[!] Invalid namespace: {}", e);
                return;
            }
            if let Some(existing) = find_case_conflict(config.hooks.keys(), namespace) {
                eprintln!(
                    "[!] Namespace '{}' conflicts with existing namespace '{}': Windows filesystems are case-insensitive, so these would collide on the same shim files.",
                    namespace, existing
                );
                eprintln!("    Use '{}' (matching the existing casing), or pick a different name.", existing);
                return;
            }
            register_namespace(namespace, path, &shim_dir, &mut config, &config_path, *dry_run);
        }

        Commands::Delete { target, binary, yes } => {
            if let Some(entry) = config.hooks.get_mut(target) {
                if binary == "all" {
                    let bin_count = entry.binaries.len();
                    let alias_count = entry.aliases.len();

                    if !*yes {
                        print!(
                            "This will unhook all {} binaries and {} aliases under namespace '{}'. Continue? [y/n]: ",
                            bin_count, alias_count, target
                        );
                        if !confirm() {
                            println!("Aborted.");
                            return;
                        }
                    }

                    let mut failures = Vec::new();
                    for bin in &entry.binaries {
                        if let Err(e) = remove_shim_pair(&shim_dir, target, bin) {
                            failures.push(format!("{}-{}: {}", target, bin, e));
                        }
                    }
                    for alias in entry.aliases.keys() {
                        if let Err(e) = remove_shim_pair(&shim_dir, target, alias) {
                            failures.push(format!("{}-{}: {}", target, alias, e));
                        }
                    }
                    config.hooks.remove(target);
                    save_config(&config_path, &config);

                    println!(
                        "[-] Unhooked all {} binaries and {} aliases from namespace '{}'",
                        bin_count, alias_count, target
                    );
                    if !failures.is_empty() {
                        eprintln!("[!] {} shim file(s) could not be removed from disk (config entry was still cleared):", failures.len());
                        for f in failures {
                            eprintln!("      {}", f);
                        }
                    }
                } else if entry.binaries.contains(binary) {
                    let mut failures = Vec::new();
                    if let Err(e) = remove_shim_pair(&shim_dir, target, binary) {
                        failures.push(format!("{}-{}: {}", target, binary, e));
                    }
                    entry.binaries.retain(|b| b != binary);

                    let dependent_aliases: Vec<String> = entry
                        .aliases
                        .iter()
                        .filter(|(_, src)| *src == binary)
                        .map(|(a, _)| a.clone())
                        .collect();
                    for alias in &dependent_aliases {
                        if let Err(e) = remove_shim_pair(&shim_dir, target, alias) {
                            failures.push(format!("{}-{}: {}", target, alias, e));
                        }
                        entry.aliases.remove(alias);
                    }

                    save_config(&config_path, &config);
                    println!("[-] Unhooked '{}-{}'", target, binary);
                    if !dependent_aliases.is_empty() {
                        println!(
                            "    Also removed {} dependent alias(es): {}",
                            dependent_aliases.len(),
                            dependent_aliases
                                .iter()
                                .map(|a| format!("{}-{}", target, a))
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                    }
                    if !failures.is_empty() {
                        eprintln!("[!] Some files could not be removed:");
                        for f in failures {
                            eprintln!("      {}", f);
                        }
                    }
                } else if entry.aliases.contains_key(binary) {
                    let mut failures = Vec::new();
                    if let Err(e) = remove_shim_pair(&shim_dir, target, binary) {
                        failures.push(format!("{}-{}: {}", target, binary, e));
                    }
                    entry.aliases.remove(binary);
                    save_config(&config_path, &config);
                    println!("[-] Unhooked alias '{}-{}'", target, binary);
                    if !failures.is_empty() {
                        eprintln!("[!] Some files could not be removed:");
                        for f in failures {
                            eprintln!("      {}", f);
                        }
                    }
                } else {
                    eprintln!("[!] Binary '{}-{}' not found.", target, binary);
                }
            } else {
                eprintln!("[!] Namespace '{}' is not registered.", target);
            }
        }

        Commands::List => {
            if config.hooks.is_empty() {
                println!("No active hooks found.");
                return;
            }
            println!("\nActive Hooks (~/.huk/config.json):");
            let mut names: Vec<&String> = config.hooks.keys().collect();
            names.sort();
            for ns in names {
                let entry = &config.hooks[ns];
                if entry.aliases.is_empty() {
                    println!(
                        "  - {:<12} -> {} ({} binaries)",
                        ns,
                        entry.path.display(),
                        entry.binaries.len()
                    );
                } else {
                    println!(
                        "  - {:<12} -> {} ({} binaries, {} aliases)",
                        ns,
                        entry.path.display(),
                        entry.binaries.len(),
                        entry.aliases.len()
                    );
                }
            }
        }

        Commands::Find { name } => {
            let needle = name.to_lowercase();
            let mut matches: Vec<String> = Vec::new();

            let mut names: Vec<&String> = config.hooks.keys().collect();
            names.sort();
            for ns in names {
                let entry = &config.hooks[ns];
                for bin in &entry.binaries {
                    if bin.to_lowercase().contains(&needle) {
                        matches.push(format!("{}-{}", ns, bin));
                    }
                }
                let mut alias_names: Vec<&String> = entry.aliases.keys().collect();
                alias_names.sort();
                for alias in alias_names {
                    if alias.to_lowercase().contains(&needle) {
                        let src = &entry.aliases[alias];
                        matches.push(format!("{}-{} (alias -> {}-{})", ns, alias, ns, src));
                    }
                }
            }

            if matches.is_empty() {
                println!("No binaries or aliases matching '{}' were found.", name);
            } else {
                println!("Found {} match(es) for '{}':", matches.len(), name);
                for m in matches {
                    println!("  {}", m);
                }
            }
        }

        Commands::Doctor { fix } => run_doctor(&shim_dir, &config_path, &mut config, *fix),

        Commands::Clean { yes } => {
            println!("[*] Checking for empty or stale hooks...");
            let mut to_remove = Vec::new();

            for (ns, entry) in &config.hooks {
                if !entry.path.exists() || entry.binaries.is_empty() {
                    println!("    [-] Stale hook detected: '{}' ({})", ns, entry.path.display());
                    to_remove.push(ns.clone());
                }
            }

            if to_remove.is_empty() {
                println!("    [\u{2713}] Everything clean. No stale hooks found.");
            } else {
                if !*yes {
                    print!("This will remove {} stale namespace(s) and their shim files. Continue? [y/n]: ", to_remove.len());
                    if !confirm() {
                        println!("Aborted.");
                        return;
                    }
                }

                let mut failures = Vec::new();
                for ns in to_remove {
                    if let Some(entry) = config.hooks.remove(&ns) {
                        for bin in entry.binaries {
                            if let Err(e) = remove_shim_pair(&shim_dir, &ns, &bin) {
                                failures.push(format!("{}-{}: {}", ns, bin, e));
                            }
                        }
                        for alias in entry.aliases.keys() {
                            if let Err(e) = remove_shim_pair(&shim_dir, &ns, alias) {
                                failures.push(format!("{}-{}: {}", ns, alias, e));
                            }
                        }
                    }
                }
                save_config(&config_path, &config);
                println!("[+] Cleaned up stale hooks.");
                if !failures.is_empty() {
                    eprintln!("[!] {} shim file(s) could not be removed from disk (config entries were still cleared):", failures.len());
                    for f in failures {
                        eprintln!("      {}", f);
                    }
                }
            }
        }

        Commands::Scan { interactive } => {
            println!("[*] Scanning common toolchain locations...\n");

            let mut candidates = vec![
                ("ucrt", PathBuf::from("C:\\msys64\\ucrt64\\bin")),
                ("mingw", PathBuf::from("C:\\msys64\\mingw64\\bin")),
                ("clang64", PathBuf::from("C:\\msys64\\clang64\\bin")),
                ("llvm", PathBuf::from("C:\\Program Files\\LLVM\\bin")),
                ("cargo", home_dir.join(".cargo\\bin")),
                ("go", home_dir.join("go\\bin")),
            ];

            let msvc_base = PathBuf::from("C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC");
            if msvc_base.exists() {
                if let Ok(entries) = fs::read_dir(&msvc_base) {
                    for entry in entries.flatten() {
                        let bin_path = entry.path().join("bin\\Hostx64\\x64");
                        if bin_path.exists() {
                            candidates.push(("msvc", bin_path));
                            break;
                        }
                    }
                }
            }

            let mut found = Vec::new();

            for (ns, path) in candidates {
                if path.exists() {
                    let has_bins = fs::read_dir(&path)
                        .map(|entries| entries.flatten().any(|e| classify(&e.path()).is_some()))
                        .unwrap_or(false);

                    if has_bins {
                        println!("  [+] Found: {:<10} -> {}", ns, path.display());
                        found.push((ns, path));
                    }
                }
            }

            if found.is_empty() {
                println!("  [-] No unhooked toolchains detected.");
                return;
            }

            if *interactive {
                println!("\n--- Interactive Hooking ---");
                for (ns, path) in found {
                    if config.hooks.contains_key(ns) {
                        println!("  [*] Skipping '{}' (already registered)", ns);
                        continue;
                    }

                    print!("Hook '{}' ({})? [y/n]: ", ns, path.display());
                    io::stdout().flush().ok();

                    let mut input = String::new();
                    io::stdin().read_line(&mut input).ok();

                    if input.trim().eq_ignore_ascii_case("y") {
                        register_namespace(ns, &path, &shim_dir, &mut config, &config_path, false);
                    }
                }
            } else {
                println!("\nRun 'huk scan -i' to interactively hook discovered paths.");
            }
        }

        Commands::Info { namespace } => {
            if let Some(entry) = config.hooks.get(namespace) {
                println!("\nNamespace: {}", namespace);
                println!("Path:      {}", entry.path.display());
                println!("Binaries:  {} total", entry.binaries.len());
                println!("Aliases:   {} total\n", entry.aliases.len());

                println!("-----Namespace-----");
                let bin_names: Vec<String> = entry.binaries.iter().map(|b| format!("{}-{}", namespace, b)).collect();
                print_columns(&bin_names);

                if !entry.aliases.is_empty() {
                    println!("\n-----Alias-----");
                    let mut alias_names: Vec<&String> = entry.aliases.keys().collect();
                    alias_names.sort();
                    for alias in alias_names {
                        let src = &entry.aliases[alias];
                        println!("  {:<25} -> {}",format!("{}-{}", namespace, alias),format!("{}-{}", namespace, src));
                    }
                }
                println!();
            } else {
                eprintln!("[!] Namespace '{}' is not registered.", namespace);
            }
        }

        // Handle early return variant explicitly
        Commands::Completions { .. } => unreachable!(),

        Commands::Alias { namespace, binary, alias } => {
            let mut succeeded = false;

            if let Err(e) = validate_name("alias", alias) {
                eprintln!("[!] Invalid alias: {}", e);
                return;
            }

            if let Some(entry) = config.hooks.get_mut(namespace) {
                let case_conflict = find_case_conflict(entry.binaries.iter(), alias)
                    .or_else(|| find_case_conflict(entry.aliases.keys(), alias));

                if !entry.binaries.contains(binary) {
                    eprintln!("[!] Binary '{}-{}' is not registered under namespace '{}'.", namespace, binary, namespace);
                } else if entry.binaries.contains(alias) || entry.aliases.contains_key(alias) {
                    eprintln!("[!] '{}-{}' already exists. Choose a different alias or delete it first.", namespace, alias);
                } else if let Some(existing) = case_conflict {
                    eprintln!("[!] Alias '{}-{}' conflicts with existing entry '{}-{}': Windows filesystems are case-insensitive, so these would collide on the same shim files.", namespace, alias, namespace, existing);
                } else {
                    let cmd_shim_path = shim_dir.join(format!("{}-{}.cmd", namespace, alias));
                    let original_cmd_path = shim_dir.join(format!("{}-{}.cmd", namespace, binary));

                    let bash_shim_path = shim_dir.join(format!("{}-{}", namespace, alias));
                    let original_bash_path = shim_dir.join(format!("{}-{}", namespace, binary));

                    if original_cmd_path.exists() && original_bash_path.exists() {
                        let cmd_result = fs::copy(&original_cmd_path, &cmd_shim_path);
                        let bash_result = fs::copy(&original_bash_path, &bash_shim_path);

                        match (&cmd_result, &bash_result) {
                            (Ok(_), Ok(_)) => {
                                entry.aliases.insert(alias.clone(), binary.clone());
                                println!("[+] Created alias '{}-{}' for '{}-{}'", namespace, alias, namespace, binary);
                                succeeded = true;
                            }
                            _ => {
                                eprintln!("[!] Failed to create alias '{}-{}':", namespace, alias);
                                if let Err(e) = &cmd_result {
                                    eprintln!("      CMD shim: {}", e);
                                }
                                if let Err(e) = &bash_result {
                                    eprintln!("      Shell shim: {}", e);
                                }
                                if cmd_result.is_ok() {
                                    fs::remove_file(&cmd_shim_path).ok();
                                }
                                if bash_result.is_ok() {
                                    fs::remove_file(&bash_shim_path).ok();
                                }
                            }
                        }
                    } else {
                        eprintln!("[!] Original shims for '{}-{}' not found.", namespace, binary);
                    }
                }
            } else {
                eprintln!("[!] Namespace '{}' is not registered.", namespace);
            }

            if succeeded {
                save_config(&config_path, &config);
            }
        }

        Commands::Uninstall { yes } => {
            let ns_count = config.hooks.len();
            let total_shims: usize = config.hooks.values().map(|e| e.binaries.len() + e.aliases.len()).sum();

            if ns_count == 0 {
                println!("Nothing hooked. Nothing to uninstall.");
                return;
            }

            if !*yes {
                print!("This will remove {} namespace(s) ({} shims total) and delete config.json. Continue? [y/n]: ",ns_count, total_shims);
                if !confirm() {
                    println!("Aborted.");
                    return;
                }
            }

            let mut failures = Vec::new();
            let mut removed_count = 0;
            for (ns, entry) in &config.hooks {
                for bin in &entry.binaries {
                    match remove_shim_pair(&shim_dir, ns, bin) {
                        Ok(()) => removed_count += 1,
                        Err(e) => failures.push(format!("{}-{}: {}", ns, bin, e)),
                    }
                }
                for alias in entry.aliases.keys() {
                    match remove_shim_pair(&shim_dir, ns, alias) {
                        Ok(()) => removed_count += 1,
                        Err(e) => failures.push(format!("{}-{}: {}", ns, alias, e)),
                    }
                }
            }

            // Belt and braces: don't rely on config being perfectly in sync with disk for
            // a full uninstall. Sweep anything left in the shim directory unconditionally.
            if let Ok(entries) = fs::read_dir(&shim_dir) {
                for entry in entries.flatten() {
                    if fs::remove_file(entry.path()).is_ok() {
                        removed_count += 1;
                    }
                }
            }

            config.hooks.clear();
            if let Err(e) = fs::remove_file(&config_path) {
                if config_path.exists() {
                    eprintln!("[!] Could not remove config.json: {}", e);
                }
            }
            fs::remove_file(backup_path(&config_path)).ok();

            println!("[-] Removed {} namespace(s) and {} shim file(s) total.", ns_count, removed_count);
            if !failures.is_empty() {
                eprintln!("[!] {} tracked shim file(s) reported an error on the first pass (cleaned up by the final sweep regardless):", failures.len());
                for f in failures {
                    eprintln!("      {}", f);
                }
            }
            println!("[*] huk.exe itself was NOT deleted, and ~/.huk/shims was NOT removed from PATH. Remove those manually if you're fully uninstalling.");
        }
    }
}

/// One-time upgrade path for config.json files written before aliases got their
/// own field: anything in `binaries` that doesn't correspond to a real file in
/// the namespace's source directory is assumed to be an old-style alias and is
/// moved into `aliases` (source recorded as "unknown" since the original mapping
/// wasn't tracked). Only runs when a namespace's `aliases` map is still empty and
/// its source path is currently reachable, so it never misfires on a namespace
/// whose directory is simply offline right now.
fn migrate_legacy_aliases(config: &mut Config, config_path: &Path) {
    let mut migrated_any = false;

    for (_, entry) in config.hooks.iter_mut() {
        if !entry.aliases.is_empty() || !entry.path.exists() {
            continue;
        }

        let real_stems: HashSet<String> = match fs::read_dir(&entry.path) {
            Ok(dir_entries) => dir_entries
                .flatten()
                .filter(|e| classify(&e.path()).is_some())
                .filter_map(|e| e.path().file_stem().and_then(|s| s.to_str().map(String::from)))
                .collect(),
            Err(_) => continue,
        };

        let (real, legacy_aliases): (Vec<String>, Vec<String>) =
            entry.binaries.iter().cloned().partition(|b| real_stems.contains(b));

        if !legacy_aliases.is_empty() {
            for a in legacy_aliases {
                entry.aliases.insert(a, "unknown".to_string());
            }
            entry.binaries = real;
            migrated_any = true;
        }
    }

    if migrated_any {
        save_config(config_path, config);
        println!("[*] Upgraded config.json: separated existing aliases from real binaries.");
        println!("    Their original source binary couldn't be recovered, so it's recorded as 'unknown'.");
        println!("    Run 'huk info <namespace>' to review, and re-create with 'huk alias' if needed.\n");
    }
}

/// Runs every doctor check. When `fix` is true, attempts to repair each issue found:
/// persists the shim dir onto the User PATH, restores config.json from its backup if
/// corrupt, regenerates missing shims for namespaces whose source dir is reachable,
/// and deletes untracked orphan shim files.
fn run_doctor(shim_dir: &Path, config_path: &Path, config: &mut Config, fix: bool) {
    println!("[*] Running Huk health check...");
    println!("    Shim Directory: {}", shim_dir.display());

    let mut issues = 0;
    let mut fixed = 0;

    // 1. PATH check
    let user_path = std::env::var("PATH").unwrap_or_default();
    if user_path.contains(shim_dir.to_str().unwrap_or("")) {
        println!("    [\u{2713}] ~/.huk/shims is present in active PATH");
    } else if fix {
        match add_shim_dir_to_path(shim_dir) {
            Ok(()) => {
                println!("    [\u{2713}] Added ~/.huk/shims to your User PATH (restart your terminal for it to take effect)");
                fixed += 1;
            }
            Err(e) => {
                println!("    [!] WARNING: ~/.huk/shims is NOT in current PATH, and automatic fix failed: {}", e);
                println!("        Add it manually in System Properties > Environment Variables, or run:");
                println!("        [Environment]::SetEnvironmentVariable('Path', $env:Path + ';{}', 'User')", shim_dir.display());
                issues += 1;
            }
        }
    } else {
        println!("    [!] WARNING: ~/.huk/shims is NOT found in current PATH.");
        println!("        Run 'huk doctor --fix' to add it automatically, or add it yourself.");
        issues += 1;
    }

    // 2. config.json validity
    let config_ok = if config_path.exists() {
        match fs::read_to_string(config_path) {
            Ok(content) => match serde_json::from_str::<Config>(&content) {
                Ok(_) => {
                    println!("    [\u{2713}] config.json parses correctly");
                    true
                }
                Err(e) => {
                    println!("    [!] config.json is present but failed to parse: {}", e);
                    false
                }
            },
            Err(e) => {
                println!("    [!] config.json exists but could not be read: {}", e);
                false
            }
        }
    } else {
        println!("    [*] No config.json yet (nothing hooked so far)");
        true
    };

    if !config_ok {
        let backup = backup_path(config_path);
        if fix {
            match fs::read_to_string(&backup).ok().and_then(|c| serde_json::from_str::<Config>(&c).ok()) {
                Some(restored) => {
                    if let Err(e) = fs::copy(&backup, config_path) {
                        println!("    [!] Found a valid backup but failed to restore it: {}", e);
                        issues += 1;
                    } else {
                        *config = restored;
                        println!("    [\u{2713}] Restored config.json from backup ({})", backup.display());
                        println!("        Re-run 'huk doctor' to verify everything else is consistent.");
                        fixed += 1;
                    }
                }
                None => {
                    println!("    [!] No valid backup found at {} to restore from.", backup.display());
                    println!("        config.json will need to be fixed or recreated by hand.");
                    issues += 1;
                }
            }
        } else {
            println!("        Run 'huk doctor --fix' to attempt restoring from {}", backup.display());
            issues += 1;
        }
        // Can't meaningfully run the remaining checks against a config we don't trust.
        println!();
        if issues == 0 {
            if fixed > 0 {
                println!("[\u{2713}] Issue repaired. Re-run 'huk doctor' to check everything else.");
            } else {
                println!("[\u{2713}] Everything looks healthy.");
            }
        } else {
            println!("[!] Found {} issue(s). See details above.", issues);
        }
        return;
    }

    // 3. Registered binaries/aliases missing their shim files on disk
    let mut affected_namespaces: HashSet<String> = HashSet::new();
    let mut missing = Vec::new();
    for (ns, entry) in config.hooks.iter() {
        for bin in &entry.binaries {
            let cmd_path = shim_dir.join(format!("{}-{}.cmd", ns, bin));
            let bash_path = shim_dir.join(format!("{}-{}", ns, bin));
            if !cmd_path.exists() && !bash_path.exists() {
                missing.push(format!("{}-{}", ns, bin));
                affected_namespaces.insert(ns.clone());
            }
        }
        for alias in entry.aliases.keys() {
            let cmd_path = shim_dir.join(format!("{}-{}.cmd", ns, alias));
            let bash_path = shim_dir.join(format!("{}-{}", ns, alias));
            if !cmd_path.exists() && !bash_path.exists() {
                missing.push(format!("{}-{} (alias)", ns, alias));
                affected_namespaces.insert(ns.clone());
            }
        }
    }

    if missing.is_empty() {
        println!("    [\u{2713}] All registered binaries and aliases have shim files on disk");
    } else if fix {
        println!("    [!] {} registered entrie(s) had no shim files on disk. Attempting repair...", missing.len());
        let mut repaired_namespaces = Vec::new();
        let mut unreachable_namespaces = Vec::new();
        for ns in &affected_namespaces {
            let source_path = config.hooks.get(ns).map(|e| e.path.clone());
            match source_path {
                Some(p) if p.exists() => {
                    register_namespace(ns, &p, shim_dir, config, config_path, false);
                    repaired_namespaces.push(ns.clone());
                }
                _ => unreachable_namespaces.push(ns.clone()),
            }
        }
        if !repaired_namespaces.is_empty() {
            println!("        [\u{2713}] Regenerated shims for: {}", repaired_namespaces.join(", "));
            fixed += 1;
        }
        if !unreachable_namespaces.is_empty() {
            println!(
                "        [!] Could not repair {} (source directory no longer exists). Run 'huk clean' to remove it.",unreachable_namespaces.join(", "));
            issues += 1;
        }
    } else {
        println!("    [!] {} registered entrie(s) have no shim files on disk:", missing.len());
        for m in &missing {
            println!("          {}", m);
        }
        println!("        Run 'huk doctor --fix' to attempt regeneration, or re-run 'huk add' yourself.");
        issues += 1;
    }

    // 4. Orphaned shim files on disk not tracked in config.json
    let mut tracked = HashSet::new();
    for (ns, entry) in &config.hooks {
        for bin in &entry.binaries {
            tracked.insert(format!("{}-{}.cmd", ns, bin));
            tracked.insert(format!("{}-{}", ns, bin));
        }
        for alias in entry.aliases.keys() {
            tracked.insert(format!("{}-{}.cmd", ns, alias));
            tracked.insert(format!("{}-{}", ns, alias));
        }
    }
    let mut orphans = Vec::new();
    if let Ok(entries) = fs::read_dir(shim_dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if !tracked.contains(name) {
                    orphans.push(entry.path());
                }
            }
        }
    }
    if orphans.is_empty() {
        println!("    [\u{2713}] No orphaned shim files in ~/.huk/shims");
    } else if fix {
        let mut removed = 0;
        let mut failed = Vec::new();
        for o in &orphans {
            match fs::remove_file(o) {
                Ok(()) => removed += 1,
                Err(e) => failed.push(format!("{}: {}", o.display(), e)),
            }
        }
        println!("    [\u{2713}] Removed {} orphaned shim file(s)", removed);
        if !failed.is_empty() {
            println!("    [!] Failed to remove {} orphan(s):", failed.len());
            for f in &failed {
                println!("          {}", f);
            }
            issues += 1;
        } else {
            fixed += 1;
        }
    } else {
        println!("    [!] {} orphaned shim file(s) in ~/.huk/shims (not tracked in config.json):", orphans.len());
        for o in &orphans {
            println!("          {}", o.display());
        }
        println!("        Run 'huk doctor --fix' to delete them.");
        issues += 1;
    }

    // 5. Case-insensitive collisions: namespaces, and binaries/aliases within a
    // namespace, that differ only by case would silently share the same shim files
    // on a case-insensitive filesystem (Windows). Not safely auto-fixable - we can't
    // know which entry the user actually wants to keep - so this is report-only even
    // under --fix.
    let mut collisions: Vec<String> = Vec::new();

    let mut ns_names: Vec<&String> = config.hooks.keys().collect();
    ns_names.sort();
    for i in 0..ns_names.len() {
        for j in (i + 1)..ns_names.len() {
            if ns_names[i].eq_ignore_ascii_case(ns_names[j]) {
                collisions.push(format!("namespaces '{}' and '{}'", ns_names[i], ns_names[j]));
            }
        }
    }

    for (ns, entry) in &config.hooks {
        let mut names: Vec<String> = entry.binaries.clone();
        names.extend(entry.aliases.keys().cloned());
        names.sort();
        for i in 0..names.len() {
            for j in (i + 1)..names.len() {
                if names[i].eq_ignore_ascii_case(&names[j]) && names[i] != names[j] {
                    collisions.push(format!("'{}-{}' and '{}-{}'", ns, names[i], ns, names[j]));
                }
            }
        }
    }

    if collisions.is_empty() {
        println!("    [\u{2713}] No case-insensitive naming collisions");
    } else {
        println!("    [!] {} case-insensitive naming collision(s) found (these share the same file on Windows):", collisions.len());
        for c in &collisions {
            println!("          {}", c);
        }
        println!("        Not auto-fixable - decide which to keep and remove the other with 'huk delete'.");
        issues += 1;
    }

    println!();
    if issues == 0 {
        if fixed > 0 {
            println!("[\u{2713}] All issues repaired. Everything looks healthy now.");
        } else {
            println!("[\u{2713}] Everything looks healthy.");
        }
    } else {
        println!("[!] Found {} issue(s) that still need attention.{}", issues, if fixed > 0 { format!(" ({} were auto-fixed)", fixed) } else { String::new() });
    }
}

/// Persists `shim_dir` onto the current user's PATH environment variable via the
/// .NET Environment API (through a one-off PowerShell invocation), which - unlike
/// `setx` - won't silently truncate a long PATH. Requires restarting any already-open
/// terminal to take effect, since env var changes don't propagate to running shells.
fn add_shim_dir_to_path(shim_dir: &Path) -> Result<(), String> {
    let shim_str = shim_dir.to_string_lossy().replace('\'', "''");
    let script = format!(
        "$cur = [Environment]::GetEnvironmentVariable('Path','User'); \
        if ($cur -notlike '*{0}*') {{ [Environment]::SetEnvironmentVariable('Path', $cur.TrimEnd(';') + ';{0}', 'User') }}",shim_str);

    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|e| format!("failed to invoke powershell: {}", e))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(if stderr.trim().is_empty() {
            format!("powershell exited with {}", output.status)
        } else {
            stderr.trim().to_string()
        })
    }
}

fn register_namespace(
    namespace: &str,
    path: &Path,
    shim_dir: &Path,
    config: &mut Config,
    config_path: &Path,
    dry_run: bool,
) {
    println!("[+] Scanning for executables in {}...", path.display());

    let mut hooked_bins = Vec::new();
    let mut seen_lower: HashSet<String> = HashSet::new();

    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            let kind = match classify(&entry_path) {
                Some(k) => k,
                None => continue,
            };

            let stem = match entry_path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s,
                None => {
                    eprintln!("[!] Skipping file with unreadable name: {}", entry_path.display());
                    continue;
                }
            };

            // Two source files differing only by case (e.g. "Tool.exe" and "tool.bat")
            // would write to the same shim files on a case-insensitive filesystem,
            // silently clobbering one another. Keep the first, skip the rest.
            if !seen_lower.insert(stem.to_lowercase()) {
                eprintln!("[!] Skipping '{}': another file in this directory already maps to the shim name '{}' (case-insensitively).",entry_path.display(),stem);
                continue;
            }

            if dry_run {
                hooked_bins.push(stem.to_string());
                continue;
            }

            if write_shim_pair(shim_dir, namespace, stem, &entry_path, path, kind) {
                hooked_bins.push(stem.to_string());
            }
        }
    }

    if hooked_bins.is_empty() {
        println!("[!] Warning: 0 executables found in {}. Skipping registration.", path.display());
        return;
    }

    if dry_run {
        println!("[dry-run] Would hook {} binaries under namespace '{}':", hooked_bins.len(), namespace);
        hooked_bins.sort();
        for b in &hooked_bins {
            println!("    {}-{}", namespace, b);
        }

        if let Some(existing) = config.hooks.get(namespace) {
            let removed: Vec<&String> = existing.binaries.iter().filter(|b| !hooked_bins.contains(b)).collect();
            if !removed.is_empty() {
                println!("[dry-run] Would unhook {} binarie(s) no longer found on disk: {}",removed.len(),removed.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "));
            }
            let dropped_aliases: Vec<&String> = existing
                .aliases
                .iter()
                .filter(|(_, src)| !hooked_bins.contains(src))
                .map(|(a, _)| a)
                .collect();
            if !dropped_aliases.is_empty() {
                println!("[dry-run] Would drop {} alias(es) whose source binary is gone: {}",dropped_aliases.len(),dropped_aliases.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "));
            }
        }

        println!("[dry-run] No files were written and config.json was not changed.");
        return;
    }

    // Carry forward aliases whose source binary is still present, recreating their
    // shim files if those happened to go missing (this is what lets 'doctor --fix'
    // repair a namespace just by calling this function again). Drop (and clean up
    // the shim for) any alias whose source binary vanished, and report real binaries
    // that used to be registered but are no longer found on disk.
    let mut carried_aliases: HashMap<String, String> = HashMap::new();
    if let Some(existing) = config.hooks.get(namespace) {
        let removed_bins: Vec<String> = existing
            .binaries
            .iter()
            .filter(|b| !hooked_bins.contains(b))
            .cloned()
            .collect();
        for b in &removed_bins {
            remove_shim_pair(shim_dir, namespace, b).ok();
        }
        if !removed_bins.is_empty() {
            println!("[*] {} binarie(s) no longer found in {} and were unhooked: {}",removed_bins.len(),path.display(),removed_bins.join(", "));
        }

        for (alias, source) in &existing.aliases {
            if hooked_bins.contains(source) {
                carried_aliases.insert(alias.clone(), source.clone());

                let alias_cmd = shim_dir.join(format!("{}-{}.cmd", namespace, alias));
                let alias_bash = shim_dir.join(format!("{}-{}", namespace, alias));
                if !alias_cmd.exists() || !alias_bash.exists() {
                    let src_cmd = shim_dir.join(format!("{}-{}.cmd", namespace, source));
                    let src_bash = shim_dir.join(format!("{}-{}", namespace, source));
                    if src_cmd.exists() && src_bash.exists() {
                        fs::copy(&src_cmd, &alias_cmd).ok();
                        fs::copy(&src_bash, &alias_bash).ok();
                        println!("[*] Recreated missing shim for alias '{}-{}'", namespace, alias);
                    }
                }
            } else {
                remove_shim_pair(shim_dir, namespace, alias).ok();
                println!("[*] Dropped alias '{}-{}' (source '{}-{}' no longer exists)", namespace, alias, namespace, source);
            }
        }
    }

    println!("[+] Hooked {} binaries (CMD & Bash shims) under namespace '{}' into {}", hooked_bins.len(), namespace, shim_dir.display());

    config.hooks.insert(
        namespace.to_string(),
        HookEntry {
            path: path.to_path_buf(),
            binaries: hooked_bins,
            aliases: carried_aliases,
        },
    );

    save_config(config_path, config);
}

/// Writes the CMD and shell shim for a single source file, choosing the right
/// invocation style for its kind (plain exe, .bat/.cmd, or .ps1). Returns true if
/// at least one of the two shims was written successfully.
fn write_shim_pair(
    shim_dir: &Path,
    namespace: &str,
    stem: &str,
    source_path: &Path,
    dir_path: &Path,
    kind: SourceKind,
) -> bool {
    let cmd_shim_path = shim_dir.join(format!("{}-{}.cmd", namespace, stem));
    let bash_shim_path = shim_dir.join(format!("{}-{}", namespace, stem));

    let (cmd_content, bash_content) = match kind {
        SourceKind::Exe => (
            format!("@echo off\r\nsetlocal\r\nset \"PATH={};%PATH%\"\r\n\"{}\" %*\r\nendlocal\r\n",dir_path.display(),source_path.display()),
            format!("#!/usr/bin/env sh\nPATH=\"{}:$PATH\"\nexec \"{}\" \"$@\"\n",to_posix(dir_path),to_posix(source_path)),
        ),
        SourceKind::BatCmd => (
            format!(
                "@echo off\r\nsetlocal\r\nset \"PATH={};%PATH%\"\r\ncall \"{}\" %*\r\nendlocal\r\n", dir_path.display(), source_path.display()),
            // Delegate to cmd.exe for .bat/.cmd sources - bash can't execute them
            // directly. Double-slash on /c avoids MSYS2 rewriting it as a root path.
            format!("#!/usr/bin/env sh\nexec cmd.exe //c \"{}\" \"$@\"\n", source_path.display()
            ),
        ),
        SourceKind::Ps1 => (
            format!( "@echo off\r\nsetlocal\r\nset \"PATH={};%PATH%\"\r\npowershell -NoProfile -ExecutionPolicy Bypass -File \"{}\" %*\r\nendlocal\r\n", dir_path.display(),source_path.display()
            ),
            format!("#!/usr/bin/env sh\nexec powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"{}\" \"$@\"\n", source_path.display()),
        ),
    };

    let cmd_ok = fs::write(&cmd_shim_path, cmd_content).is_ok();
    let bash_ok = fs::write(&bash_shim_path, bash_content).is_ok();
    cmd_ok || bash_ok
}

/// Returns the backup path for a given config.json path (e.g. config.json.bak).
fn backup_path(config_path: &Path) -> PathBuf {
    let mut p = config_path.as_os_str().to_os_string();
    p.push(".bak");
    PathBuf::from(p)
}

/// Writes config to disk, first best-effort backing up whatever was there before
/// (one rotating backup, not a full history) so a bad write or later corruption
/// has something for `huk doctor --fix` to restore from.
fn save_config(path: &Path, config: &Config) {
    if path.exists() {
        fs::copy(path, backup_path(path)).ok();
    }

    let json = match serde_json::to_string_pretty(config) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("[!] Failed to serialize config: {}", e);
            eprintln!("    Nothing was saved. Your last change was NOT persisted to config.json.");
            return;
        }
    };

    if let Err(e) = fs::write(path, json) {
        eprintln!("[!] Failed to write config.json: {}", e);
        eprintln!("    Nothing was saved. Your last change was NOT persisted to config.json.");
    }
}

/// Removes both the CMD and shell shim for a binary. Returns Err with a combined
/// message if either removal fails for a reason other than "already gone".
fn remove_shim_pair(shim_dir: &Path, namespace: &str, binary: &str) -> Result<(), String> {
    let cmd_path = shim_dir.join(format!("{}-{}.cmd", namespace, binary));
    let bash_path = shim_dir.join(format!("{}-{}", namespace, binary));

    let mut errors = Vec::new();
    if let Err(e) = fs::remove_file(&cmd_path) {
        if cmd_path.exists() {
            errors.push(format!("{}: {}", cmd_path.display(), e));
        }
    }
    if let Err(e) = fs::remove_file(&bash_path) {
        if bash_path.exists() {
            errors.push(format!("{}: {}", bash_path.display(), e));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Reads a y/n confirmation from stdin. Defaults to "no" on empty input or read failure.
fn confirm() -> bool {
    io::stdout().flush().ok();
    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(_) => input.trim().eq_ignore_ascii_case("y"),
        Err(_) => false,
    }
}

/// Prints a list of names in a column grid sized to the terminal width, instead of a
/// fixed column count. Column width comes from the longest name in THIS list (plus
/// padding), so short lists get tight columns and long names still fit; column count
/// is however many of those fit within the target width. Width is detected from the
/// real terminal via the `terminal_size` crate, falling back to the COLUMNS env var,
/// then a 100-char default if neither is available (e.g. output is piped).
fn print_columns(items: &[String]) {
    if items.is_empty() {
        return;
    }

    let target_width: usize = terminal_size::terminal_size()
        .map(|(terminal_size::Width(w), _)| w as usize)
        .or_else(|| std::env::var("COLUMNS").ok().and_then(|v| v.parse().ok()))
        .unwrap_or(100);

    let longest = items.iter().map(|s| s.len()).max().unwrap_or(0);
    let col_width = longest + 2;

    let columns = (target_width / col_width).max(1);

    for (i, item) in items.iter().enumerate() {
        print!("  {:<width$}", item, width = col_width);
        if (i + 1) % columns == 0 {
            println!();
        }
    }
    if items.len() % columns != 0 {
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_detects_known_extensions() {
        assert!(matches!(classify(Path::new("foo.exe")), Some(SourceKind::Exe)));
        assert!(matches!(classify(Path::new("foo.EXE")), Some(SourceKind::Exe)));
        assert!(matches!(classify(Path::new("foo.bat")), Some(SourceKind::BatCmd)));
        assert!(matches!(classify(Path::new("foo.cmd")), Some(SourceKind::BatCmd)));
        assert!(matches!(classify(Path::new("foo.ps1")), Some(SourceKind::Ps1)));
        assert!(classify(Path::new("foo.txt")).is_none());
        assert!(classify(Path::new("foo")).is_none());
    }

    #[test]
    fn backup_path_appends_bak() {
        let p = Path::new("/home/user/.huk/config.json");
        assert_eq!(backup_path(p), PathBuf::from("/home/user/.huk/config.json.bak"));
    }

    #[test]
    fn print_columns_handles_empty_list() {
        // Should not panic on an empty slice.
        print_columns(&[]);
    }

    #[test]
    fn validate_name_rejects_reserved_chars() {
        assert!(validate_name("namespace", "ucrt").is_ok());
        assert!(validate_name("namespace", "").is_err());
        assert!(validate_name("namespace", ".").is_err());
        assert!(validate_name("namespace", "..").is_err());
        assert!(validate_name("namespace", "foo/bar").is_err());
        assert!(validate_name("namespace", "foo:bar").is_err());
        assert!(validate_name("namespace", "foo*bar").is_err());
    }

    #[test]
    fn find_case_conflict_ignores_exact_match_and_finds_case_variants() {
        let keys = vec!["ucrt".to_string(), "mingw".to_string()];
        assert_eq!(find_case_conflict(keys.iter(), "ucrt"), None); // exact match, not a conflict
        assert_eq!(find_case_conflict(keys.iter(), "UCRT"), Some(&"ucrt".to_string()));
        assert_eq!(find_case_conflict(keys.iter(), "clang"), None);
    }
}
