use cfg_aliases::cfg_aliases;

fn main() {
    // Setup cfg aliases
    cfg_aliases! {
        // Convenience aliases
        wasm_browser: { all(target_family = "wasm", target_os = "unknown") },
        // Limited POSIX platforms (not wasm)
        posix_minimal: { target_os = "espidf" },
        // Platforms where the `netdev` crate is available
        has_netdev: { not(any(posix_minimal, wasm_browser)) },
    }
}
