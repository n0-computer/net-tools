use cfg_aliases::cfg_aliases;

fn main() {
    // Setup cfg aliases
    cfg_aliases! {
        // Convenience aliases
        wasm_browser: { all(target_family = "wasm", target_os = "unknown") },
        // Limited POSIX platforms (not wasm)
        posix_minimal: { target_os = "espidf" },
    }
}
