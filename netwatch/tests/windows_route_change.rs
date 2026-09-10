//! Run through `scripts/windows-route-change.ps1` on a disposable Windows machine.
//! The harness provisions adapters and restores routes even if this test fails.
#![cfg(target_os = "windows")]

use std::{path::PathBuf, process::Command, time::Duration};

use n0_watcher::Watcher;
use netwatch::{interfaces::State, netmon::Monitor};

fn default_name(state: &State) -> String {
    let name = state
        .default_route_interface
        .as_ref()
        .expect("a default route must exist in this fixture");
    assert!(
        state.interfaces.contains_key(name),
        "default route must name a key in State::interfaces"
    );
    name.to_ascii_lowercase()
}

#[tokio::test]
#[ignore = "changes Windows routes; requires the disposable CI harness"]
async fn windows_default_route_change() {
    // The flaky-test workflow also runs ignored tests on shared runners.
    // Provisioning and mutation are only permitted in the dedicated harness.
    if std::env::var("NETWATCH_ROUTE_TEST").as_deref() != Ok("1") {
        println!("Skipping: run through scripts/windows-route-change.ps1");
        return;
    }
    let a = std::env::var("NETWATCH_ADAPTER_A_NAME")
        .unwrap()
        .to_ascii_lowercase();
    let b = std::env::var("NETWATCH_ADAPTER_B_NAME")
        .unwrap()
        .to_ascii_lowercase();
    assert_ne!(a, b);
    let monitor = Monitor::new().await.unwrap();
    let mut watcher = monitor.interface_state();
    let mut old = watcher.get();
    println!("Initial state: {old:#}");
    assert_eq!(default_name(&old), a);

    // Both adapters and their addresses already exist. Only route metrics change,
    // so an adapter appearing cannot mask a broken default-route lookup.
    for (action, expected) in [
        ("PreferB", &b),
        ("PreferA", &a),
        ("PreferB", &b),
        ("PreferA", &a),
    ] {
        let output = tokio::task::spawn_blocking(move || {
            Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-File"])
                .arg(
                    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("../scripts/windows-route-change.ps1"),
                )
                .args(["-Action", action])
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        println!("{}", String::from_utf8_lossy(&output.stdout));
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );

        // Do not call Monitor::network_change(): Windows must deliver the event.
        let new = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let state = watcher.updated().await.unwrap();
                println!("Observed state: {state:#}");
                if &default_name(&state) == expected {
                    break state;
                }
            }
        })
        .await
        .expect("Windows route change did not reach the monitor within 20 seconds");
        assert_ne!(new.default_route_interface, old.default_route_interface);
        assert!(new.is_major_change(&old));
        assert_eq!(&default_name(&State::new().await), expected);
        old = new;
    }
}
