use std::process::Command;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=src/shaders.metal");
    println!("cargo:rerun-if-changed=shaders.metallib");

    if !cfg!(target_os = "macos") {
        eprintln!("[-] Metal is available only on macOS. GPU acceleration is disabled!");
        eprintln!("[!] This programm was created only for macOS - never tested on other OS");
        return;
    }

    let shader_path = "src/shaders.metal";
    let air_path = "shaders.air";
    let lib_path = "shaders.metallib";

    if !Path::new(shader_path).exists() {
        panic!("[-] Shader-File not found: {}", shader_path);
    }

    println!("[*] Compile Metal Shaders...");

    let status = Command::new("xcrun")
        .args(&[
            "-sdk", "macosx",
            "metal",
            "-c",
            shader_path,
            "-o", air_path,
            "-O3",
            "-ffast-math",
        ])
        .status()
        .expect("[-] xcrun metal not found - is Xcode installed?");

    if !status.success() {
        panic!("[-] Metal shader compilation failed");
    }

    println!("[!] Shader Compiled");

    let status = Command::new("xcrun")
        .args(&[
            "-sdk", "macosx",
            "metallib",
            air_path,
            "-o", lib_path,
        ])
        .status()
        .expect("[-] xcrun metallib not found");

    if !status.success() {
        panic!("[-] Metal library creation failed");
    }

    println!("[-] Metal Library created: {}", lib_path);

    let _ = std::fs::remove_file(air_path);
}