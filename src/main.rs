mod gpu_decoder;
mod ui;

use anyhow::{bail, Result};
use base64::engine::general_purpose;
use base64::Engine as _;
use gpu_decoder::GpuDecoder;
use std::collections::VecDeque;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use ui::{AppState, Status};

const MESSAGE_FILE: &str = "message.txt";
const WORDLIST_FILE: &str = "words.txt";

fn load_wordlist() -> Result<Vec<Vec<String>>> {
    if !Path::new(WORDLIST_FILE).exists() {
        bail!("[-] Word list file not found: {}", WORDLIST_FILE);
    }
    let content = fs::read_to_string(WORDLIST_FILE)?;

    let mut panels: Vec<Vec<String>> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for (line_idx, line) in content.lines().take(8).enumerate() {
        let mut words: Vec<String> = Vec::new();
        for token in line.split(',') {
            let w = token.to_lowercase();
            if w.is_empty() { continue; }
            let n = w.chars().count();
            if n != 4 {
                errors.push(format!(
                    "[!] Row {}: '{}' has {} Character - exactly 4 are allowed",
                    line_idx + 1, w, n
                ));
            }
            words.push(w);
        }
        panels.push(words);
    }

    if panels.len() != 8 {
        bail!("[!] The word list must have exactly 8 lines (currently: {})", panels.len());
    }

    if !errors.is_empty() {
        let shown: Vec<String> = errors.iter().take(20).cloned().collect();
        let more = errors.len().saturating_sub(shown.len());
        let mut msg = format!("[-] Word list validation failed ({} error):", errors.len());
        for e in shown { msg.push_str(&format!("\n  - {}", e)); }
        if more > 0 { msg.push_str(&format!("\n  - ... and {} more", more)); }
        bail!("{}", msg);
    }

    Ok(panels)
}

fn load_message() -> Result<Vec<u8>> {
    let content = fs::read_to_string(MESSAGE_FILE)?;
    let clean = content.replace('\n', "").replace('\r', "");
    match general_purpose::STANDARD.decode(&clean) {
        Ok(d) => Ok(d),
        Err(e) => {
            let fixed = clean.trim().trim_matches('"');
            general_purpose::STANDARD.decode(fixed)
                .map_err(|e2| anyhow::anyhow!("[-] Base64-Error: {} / {}", e, e2))
        }
    }
}

fn main() -> Result<()> {
let debug_mode = matches!(
    std::env::var("GPU_DEBUG").ok().as_deref(),
    Some("1") | Some("true") | Some("TRUE")
);

if debug_mode { run_debug_mode() } else { run_tui_mode() }
}

// ============================================================================
// DEBUG-MODE (GPU_DEBUG=1)
// ============================================================================
fn run_debug_mode() -> Result<()> {
    println!("Arweave Puzzle #3 Metal-Decoder v1.0 by github.com/arturfromtheblock [DEBUG-MODE]");
    println!("{}", "=".repeat(60));

    let gpu = GpuDecoder::new()?;
    let batch_size = gpu.optimal_batch_size();
    println!("[*] {}", gpu.device_info());

    let ciphertext = Arc::new(load_message()?);
    println!("[*] Ciphertext loaded: {} bytes", ciphertext.len());

    let panels = load_wordlist()?;
    let mut total: u128 = 1;
    let mut panel_sizes = Vec::new();
    println!("");
    for (i, panel) in panels.iter().enumerate() {
        let size = panel.len();
        panel_sizes.push(size);
        total = total.saturating_mul(size as u128);
        let size_str = format!("[*] Panel {:>2}: {:>8} words", i+1, size);
        println!("{:<58}", size_str);
    }
    println!("");
    let total_formatted = format_number(total);
    println!("[*] Combinations: {:>10} ", total_formatted);
    println!("");
    println!();

    let found = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let mut result_found: Option<(String, String)> = None;

    // Progress-Thread
    {
        let c = counter.clone();
        let f = found.clone();
        std::thread::spawn(move || {
            let mut last_count = 0u64;
            let mut last_time = Instant::now();
            loop {
                std::thread::sleep(Duration::from_secs(2));
                if f.load(Ordering::Relaxed) { break; }
                let now_count = c.load(Ordering::Relaxed);
                let now_time = Instant::now();
                let delta = now_count.saturating_sub(last_count);
                let elapsed = now_time.duration_since(last_time).as_secs_f64();
                if elapsed > 0.9 && delta > 0 {
                    let speed = delta as f64 / elapsed;
                    let total_elapsed = now_time.duration_since(start).as_secs_f64();
                    eprint!("\r[{:>5.0}s] | {:>8}/s | Tested: {:>10}      ",
                           total_elapsed, speed as u64, now_count);
                }
                last_count = now_count;
                last_time = now_time;
            }
        });
    }

    println!("\nStarting work...\n");
    let mut chunk_buffer = Vec::with_capacity(batch_size);

    'outer: for w1 in &panels[0] {
        for w2 in &panels[1] {
            for w3 in &panels[2] {
                for w4 in &panels[3] {
                    for w5 in &panels[4] {
                        for w6 in &panels[5] {
                            for w7 in &panels[6] {
                                for w8 in &panels[7] {
                                    if found.load(Ordering::Relaxed) { break 'outer; }
                                    let pass = format!("{}{}{}{}{}{}{}{}", w1, w2, w3, w4, w5, w6, w7, w8);
                                    chunk_buffer.push(pass);

                                    if chunk_buffer.len() >= batch_size {
                                        match gpu.process_batch(&ciphertext, &chunk_buffer) {
                                            Ok(Some((_idx, passphrase, decrypted))) => {
                                                found.store(true, Ordering::SeqCst);
                                                result_found = Some((passphrase, decrypted));
                                                break 'outer;
                                            }
                                            Ok(None) => {
                                                counter.fetch_add(chunk_buffer.len() as u64, Ordering::Relaxed);
                                                chunk_buffer.clear();
                                            }
                                            Err(e) => {
                                                eprintln!("[-] GPU-Error: {}", e);
                                                chunk_buffer.clear();
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if !chunk_buffer.is_empty() && !found.load(Ordering::Relaxed) {
        match gpu.process_batch(&ciphertext, &chunk_buffer) {
            Ok(Some((_idx, passphrase, decrypted_content))) => {
                found.store(true, Ordering::SeqCst);
                result_found = Some((passphrase, decrypted_content));
            }
            Ok(None) => {
                counter.fetch_add(chunk_buffer.len() as u64, Ordering::Relaxed);
            }
            Err(e) => {
                eprintln!("\n[-] GPU-Error in the last batch: {}", e);
            }
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    let tested_count = counter.load(Ordering::Relaxed);
    println!();

    match result_found {
        Some((pass, content)) => {
            println!("\n{}", "=".repeat(60));
            println!("[!] HIT FOUND!");
            println!("{}", "=".repeat(60));
            println!("\n[!] Passphrase: {}", pass);
            println!("[*]  Time: {:.2} seconds", elapsed);
            println!("[*] Tested: {}", tested_count);
            println!("[*] Speed: {:.0} Tests/s", tested_count as f64 / elapsed);
            println!("[+] Saving in decrypted.json...");
            std::fs::write("decrypted.json", &content)?;
            println!("[+] Saved!");
        }
        None => {
            println!("\n{}", "=".repeat(60));
            println!("[-] No hit");
            println!("{}", "=".repeat(60));
            println!("\n[*] Stats:");
            println!("  [*] Tested: {}", tested_count);
            println!("  [*] Time: {:.2} seconds", elapsed);
            println!("  [*] Speed: {:.0} Tests/s", tested_count as f64 / elapsed);
        }
    }
    Ok(())
}

fn run_tui_mode() -> Result<()> {
    let state = Arc::new(Mutex::new(AppState {
        status: Status::Starting,
        paused: false,
        tested: 0,
        total: 0,
        speed: 0.0,
        elapsed: Duration::ZERO,
        current_pass: String::new(),
        panels: vec![],
        log: VecDeque::new(),
        found_pass: None,
        recent_passes: VecDeque::new(),
        batch_no: 0,
        updated_at: Instant::now(),
    }));
    {
        let mut s = state.lock().unwrap();
        s.push_log("[*] Programm started".into());

        match GpuDecoder::new_quiet() {
            Ok(_gpu) => {
                s.push_log(format!("[+] Metal active"));
            }
            Err(e) => {
                s.push_log(format!("[-] Metal-Error: {}", e));
                s.status = Status::Error;
            }
        }
    }
    let panels = match load_wordlist() {
        Ok(p) => {
            let mut s = state.lock().unwrap();
            let mut total: u128 = 1;
            for panel in &p { total = total.saturating_mul(panel.len() as u128); }
            s.total = total;
            s.panels = p.iter().map(|x| x.len()).collect();
            s.push_log(format!("[+] Word list loaded"));
            Some(p)
        }
        Err(e) => {
            let mut s = state.lock().unwrap();
            for line in e.to_string().lines() {
                let t = line.trim_end();
                if !t.is_empty() { s.push_log(format!("[-] {}", t)); }
            }
            None
        }
    };
    if panels.is_none() {
        let mut s = state.lock().unwrap();
        s.status = Status::Error;
        s.push_log("[-] Start aborted - fix word list (Q/Enter = quit)".into());
        drop(s);
        let quit = Arc::new(AtomicBool::new(false));
        ui::run(state.clone(), quit)?;
        return Ok(());
    }
    let panels = panels.unwrap();

    let ciphertext = match load_message() {
        Ok(ct) => {
            let mut s = state.lock().unwrap();
            s.push_log(format!("[+] Encrypted file loaded: {} bytes", ct.len()));
            ct
        }
        Err(e) => {
            let mut s = state.lock().unwrap();
            s.push_log(format!("[-] File error: {}", e));
            s.status = Status::Error;
            vec![]
        }
    };

    if state.lock().unwrap().status == Status::Error {
        let quit = Arc::new(AtomicBool::new(false));
        ui::run(state.clone(), quit.clone())?;
        return Ok(());
    }
    let quit = Arc::new(AtomicBool::new(false));
    let st_w = state.clone();
    let qt_w = quit.clone();
    let worker = std::thread::spawn(move || worker_run(ciphertext, panels, st_w, qt_w));

    ui::run(state.clone(), quit.clone())?;

    quit.store(true, Ordering::SeqCst);
    let result = worker.join().ok().flatten();

    match result {
        Some((pass, _content)) => {
            println!("[!] HIT: {}", pass);
            println!("[!] Saved to decrypted.json");
        }
        None => println!("[*] Programm stopped"),
    }
    Ok(())
}

fn worker_run(
    ciphertext: Vec<u8>,
    panels: Vec<Vec<String>>,
    state: Arc<Mutex<AppState>>,
    quit: Arc<AtomicBool>,
) -> Option<(String, String)> {
    let gpu = match GpuDecoder::new_quiet() {
        Ok(g) => g,
        Err(e) => {
            let mut s = state.lock().unwrap();
            s.status = Status::Error;
            s.push_log(format!("[-] GPU-Init failed: {}", e));
            return None;
        }
    };
    {
        let mut s = state.lock().unwrap();
        let total = s.total;
        s.status = Status::Running;
        s.push_log(format!("[+] GPU ready   : {}", gpu.device_info()));
        s.push_log(format!("[+] Batch size  : {}", gpu.optimal_batch_size()));
        s.push_log(format!("[+] Combinations: {} ({})", format_number(total), short_number(total)));
        s.push_log("[*] Search started...".into());
        s.updated_at = Instant::now();
    }

    let batch_size = gpu.optimal_batch_size();
    let start = Instant::now();
    let mut paused_total = Duration::ZERO;
    let mut chunk: Vec<String> = Vec::with_capacity(batch_size);
    let mut tested: u64 = 0;
    let mut last_tested: u64 = 0;
    let mut last_time = Instant::now();
    let mut batch_number: u64 = 0;
    let mut result = None;

    'outer: for w1 in &panels[0] {
        for w2 in &panels[1] {
            for w3 in &panels[2] {
                for w4 in &panels[3] {
                    for w5 in &panels[4] {
                        for w6 in &panels[5] {
                            for w7 in &panels[6] {
                                for w8 in &panels[7] {
                                    if quit.load(Ordering::Relaxed) { break 'outer; }

                                    if state.lock().unwrap().paused {
                                        {
                                            let mut s = state.lock().unwrap();
                                            s.push_log(format!("[!] Finishing batch {} then pause...", batch_number));
                                        }
                                        let pause_start = Instant::now();
                                        while state.lock().unwrap().paused && !quit.load(Ordering::Relaxed) {
                                            std::thread::sleep(Duration::from_millis(100));
                                        }
                                        paused_total += pause_start.elapsed();
                                        if quit.load(Ordering::Relaxed) { break 'outer; }
                                        let mut s = state.lock().unwrap();
                                        s.push_log(format!("[*] Resume from batch {}", batch_number));
                                        s.elapsed = start.elapsed() - paused_total;
                                        s.updated_at = Instant::now();
                                        last_time = Instant::now();
                                    }

                                    let pass = format!("{}{}{}{}{}{}{}{}", w1, w2, w3, w4, w5, w6, w7, w8);
                                    chunk.push(pass.clone());

                                    if chunk.len() % 256 == 0 {
                                        let mut s = state.lock().unwrap();
                                        s.recent_passes.push_back(pass.clone());
                                        if s.recent_passes.len() > 128 { s.recent_passes.pop_front(); }
                                    }

                                    if chunk.len() < batch_size { continue; }

                                    batch_number += 1;
                                    match gpu.process_batch(&ciphertext, &chunk) {
                                        Ok(Some((_, pass_found, dec))) => {
                                            tested += chunk.len() as u64;
                                            let saved = fs::write("decrypted.json", &dec).is_ok();
                                            let mut s = state.lock().unwrap();
                                            s.tested = tested;
                                            s.status = Status::Found;
                                            s.found_pass = Some(pass_found.clone());
                                            s.elapsed = start.elapsed() - paused_total;
                                            s.updated_at = Instant::now();
                                            s.push_log(format!("[!] HIT: {}", pass_found));
                                            s.push_log(if saved {
                                                "[!] Saved to decrypted.json".to_string()
                                            } else {
                                                "[-] Could not save decrypted.json!".to_string()
                                            });
                                            result = Some((pass_found, dec));
                                            break 'outer;
                                        }
                                        Ok(None) => { tested += chunk.len() as u64; }
                                        Err(e) => {
                                            let mut s = state.lock().unwrap();
                                            s.push_log(format!("[-] GPU-Error: {} (batch discarded)", e));
                                        }
                                    }

                                    {
                                        let now = Instant::now();
                                        let dt = now.duration_since(last_time).as_secs_f64();
                                        let inst = if dt > 0.0 { (tested - last_tested) as f64 / dt } else { 0.0 };
                                        let mut s = state.lock().unwrap();
                                        s.tested = tested;
                                        s.speed = if s.speed < 1.0 { inst } else { s.speed * 0.7 + inst * 0.3 };
                                        s.elapsed = start.elapsed() - paused_total;
                                        s.batch_no = batch_number;
                                        s.updated_at = now;
                                        last_tested = tested;
                                        last_time = now;
                                    }
                                    chunk.clear();
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if !chunk.is_empty() && result.is_none() && !quit.load(Ordering::Relaxed) {
        match gpu.process_batch(&ciphertext, &chunk) {
            Ok(Some((_, pass, dec))) => {
                tested += chunk.len() as u64;
                let mut s = state.lock().unwrap();
                s.tested = tested;
                s.status = Status::Found;
                s.found_pass = Some(pass.clone());
                s.push_log(format!("🎉 HIT: {}", pass));
                result = Some((pass, dec));
            }
            Ok(None) => { tested += chunk.len() as u64; }
            Err(e) => {
                let mut s = state.lock().unwrap();
                s.push_log(format!("[-] GPU-Error (remaining): {}", e));
            }
        }
    }

    {
        let mut s = state.lock().unwrap();
        s.tested = tested;
        s.elapsed = start.elapsed() - paused_total;
        let elapsed_secs = s.elapsed.as_secs_f64();

        if result.is_none() && s.status != Status::Error {
            s.status = Status::NoHit;
            s.push_log("[-] All combinations tested — no matches".into());
        }
        s.push_log(format!("[*] Done: {} combinations in {:.1}s ({:.0}/s)",
                        tested, elapsed_secs, tested as f64 / elapsed_secs.max(0.001)));
    }
    result
}

fn format_number(n: u128) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    let mut count = 0;
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && count == 3 {
            result.push('.');
            count = 0;
        }
        result.push(c);
        count += 1;
    }
    result.chars().rev().collect()
}

fn fmt_short(v: f64) -> String {
    let mut s = format!("{:.1}", v);
    if s.ends_with(".0") { s.truncate(s.len() - 2); }  // "1.0" -> "1"
    s.replace('.', ",")                                 // deutsches Komma
}

fn short_number(n: u128) -> String {
    if n >= 1_000_000_000_000 {
        format!("{} T", fmt_short(n as f64 / 1_000_000_000_000.0))
    } else if n >= 1_000_000_000 {
        format!("{} B", fmt_short(n as f64 / 1_000_000_000.0))
    } else if n >= 1_000_000 {
        format!("{} M", fmt_short(n as f64 / 1_000_000.0))
    } else if n >= 1_000 {
        format!("{} K", fmt_short(n as f64 / 1_000.0))
    } else {
        format!("{}", n)
    }
}