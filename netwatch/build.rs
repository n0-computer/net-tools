use cfg_aliases::cfg_aliases;

fn main() {
    // Setup cfg aliases
    cfg_aliases! {
        // Convenience aliases
        wasm_browser: { all(target_family = "wasm", target_os = "unknown") },
        // Platforms where the `netdev` crate is available
        has_netdev: { any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "ios", target_os = "windows", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd") },
    }
}
