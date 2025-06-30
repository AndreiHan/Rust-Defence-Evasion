# Rust Defence Evasion

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Rust](https://img.shields.io/badge/Rust-Process%20Mitigations-blue)

A collection of Windows process mitigation techniques implemented in Rust. These examples demonstrate how to evade userland hooks, DLL injection, and dynamic code analysis by AV/EDR solutions. Each example crate shows a different mitigation strategy, with clear code and build instructions.

---

## 🚫 Prevent Third Party DLL Loading

**Block non-Microsoft-signed DLLs from being loaded into the current process.**

### How It Works

Uses `SetProcessMitigationPolicy` with the `ProcessSignaturePolicy` class and the `SE_SIGNING_LEVEL_MICROSOFT` flag to restrict DLL loading to Microsoft-signed binaries only.

### Example Code

```rust
use windows::Win32::System::{
    SystemServices::{PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, SE_SIGNING_LEVEL_MICROSOFT},
    Threading::{ProcessSignaturePolicy, SetProcessMitigationPolicy},
};

fn prevent_third_party_dll_loading() {
    println!("Preventing third party dll loading");
    let mut policy = PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY::default();
    policy.Anonymous.Flags = SE_SIGNING_LEVEL_MICROSOFT;
    policy.Anonymous.Anonymous._bitfield = 1;
    unsafe {
        let status = SetProcessMitigationPolicy(
            ProcessSignaturePolicy,
            std::ptr::from_ref(&policy).cast(),
            std::mem::size_of_val(&policy),
        );
        println!("Set process mitigation policy status: {:?}", status);
    }
}
```

### Build & Run

```sh
cargo build --release -p prevent_third_party_loading
./target/release/prevent_third_party_loading
```

### Verification

- Use **Process Hacker** or PowerShell to confirm the mitigation policy is active on the process.
- Attempt to inject a non-Microsoft DLL; it should be blocked.

---

## 🛡️ Enable Arbitrary Code Guard (ACG)

**Prevent the process from generating or modifying executable code at runtime.**

### How It Works

Uses the Windows API `SetProcessMitigationPolicy` with the `ProcessDynamicCodePolicy` class to prohibit dynamic code generation.

### Example Code

```rust
use windows::Win32::System::{
    SystemServices::{PROCESS_MITIGATION_DYNAMIC_CODE_POLICY, SE_SIGNING_LEVEL_DYNAMIC_CODEGEN},
    Threading::{ProcessDynamicCodePolicy, SetProcessMitigationPolicy},
};

fn enable_arbitrary_code_guard() {
    let mut policy = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY::default();
    policy.Anonymous.Flags = SE_SIGNING_LEVEL_DYNAMIC_CODEGEN;
    policy.Anonymous.Anonymous._bitfield = 1;
    unsafe {
        let status = SetProcessMitigationPolicy(
            ProcessDynamicCodePolicy,
            std::ptr::from_ref(&policy).cast(),
            std::mem::size_of_val(&policy),
        );
        println!("Set process mitigation policy status: {:?}", status);
    }
}
```

### Build & Run

```sh
cargo build --release -p enable_agc
./target/release/enable_agc
```

### Verification

- Use **Process Hacker** to inspect the process and confirm the ACG policy is enabled.
- Attempting to inject a DLL that writes/executes shellcode should fail.

---

## 🕵️ Hide Thread from Debugger

**Hide the current thread from a debugger using the `NtSetInformationThread` API.**

### How It Works

Calls `NtSetInformationThread` with the `ThreadHideFromDebugger` information class on the current thread.

### Example Code

```rust
use windows::{
    Wdk::System::Threading::{NtSetInformationThread, ThreadHideFromDebugger},
    Win32::System::Threading::GetCurrentThread,
};

pub fn hide_current_thread_from_debuggers() {
    println!("Hiding current thread from debuggers");
    unsafe {
        let status = NtSetInformationThread(
            GetCurrentThread(),
            ThreadHideFromDebugger,
            std::ptr::null(),
            0,
        );
        println!("Set anti debug status: {:?}", status);
    }
}
```

### Build & Run

```sh
cargo build --release -p hide_thread_from_debugger
./target/release/hide_thread_from_debugger
```

### Verification

- Attach a debugger and observe that the thread is hidden or inaccessible.
- Use tools like x64dbg or WinDbg to confirm the effect.

---

## 📦 Example Crates

- [`prevent_third_party_loading`](./examples/prevent_third_party_loading): Block non-Microsoft-signed DLLs from being loaded into the process.
- [`enable_agc`](./examples/enable_agc): Enable Arbitrary Code Guard (ACG) to prevent dynamic code generation.
- [`hide_thread_from_debugger`](./examples/hide_thread_from_debugger): Hide the current thread from debuggers.

---

> **Disclaimer:** This repository is for educational and research purposes only.
