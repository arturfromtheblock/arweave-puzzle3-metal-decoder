use anyhow::{bail, Result};
use metal::*;
use std::mem;
use std::time::Instant;

const MAX_CT_LEN: u64 = 4096;
const OUTPUT_MAX_LEN: u64 = 4096;

fn dbg_on() -> bool {
    matches!(
        std::env::var("GPU_DEBUG").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    )
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

unsafe fn peek_bytes(buf: &Buffer, n: usize) -> Vec<u8> {
    std::slice::from_raw_parts(buf.contents() as *const u8, n).to_vec()
}

unsafe fn peek_u32(buf: &Buffer, n: usize) -> Vec<u32> {
    std::slice::from_raw_parts(buf.contents() as *const u32, n).to_vec()
}

fn count_nonzero(bytes: &[u8]) -> usize {
    bytes.iter().filter(|&&b| b != 0).count()
}

pub struct GpuDecoder {
    device: Device,
    command_queue: CommandQueue,
    pipeline_derive_keys: ComputePipelineState,
    pipeline_decrypt: ComputePipelineState,
    pipeline_postprocess: ComputePipelineState,
    info: String,
}

impl GpuDecoder {
    pub fn new() -> Result<Self> {
        let device = Device::system_default()
            .ok_or_else(|| anyhow::anyhow!("[-] No Metal-Device found!"))?;

        const SHADER_LIB: &[u8] = include_bytes!("../shaders.metallib");

        let library = device
            .new_library_with_data(SHADER_LIB)
            .map_err(|e| anyhow::anyhow!("[-] Failed to load Shader-Library: {}", e))?;

        let kernel_derive = library
            .get_function("derive_keys_batch", None)
            .map_err(|e| anyhow::anyhow!("[-] Kernel 'derive_keys_batch' not found: {}", e))?;
        let pipeline_derive_keys = device
            .new_compute_pipeline_state_with_function(&kernel_derive)
            .map_err(|e| anyhow::anyhow!("[-] Pipeline for derive_keys failed: {}", e))?;

        let kernel_decrypt = library
            .get_function("decrypt_batch", None)
            .map_err(|e| anyhow::anyhow!("[-] Kernel 'decrypt_batch' not found: {}", e))?;
        let pipeline_decrypt = device
            .new_compute_pipeline_state_with_function(&kernel_decrypt)
            .map_err(|e| anyhow::anyhow!("[-] Pipeline for decrypt failed: {}", e))?;

        let kernel_post = library
            .get_function("postprocess_batch", None)
            .map_err(|e| anyhow::anyhow!("[-] Kernel 'postprocess_batch' not found: {}", e))?;
        let pipeline_postprocess = device
            .new_compute_pipeline_state_with_function(&kernel_post)
            .map_err(|e| anyhow::anyhow!("[-] Pipeline for postprocess failed: {}", e))?;

        let info = format!(
            "{} · SIMD: {} · MaxTPG: {}",
            device.name(),
            pipeline_derive_keys.thread_execution_width(),
            pipeline_derive_keys.max_total_threads_per_threadgroup()
        );

        let command_queue = device.new_command_queue();
        Ok(Self {
            device,
            command_queue,
            pipeline_derive_keys,
            pipeline_decrypt,
            pipeline_postprocess,
            info
        })
    }

    pub fn new_quiet() -> Result<Self> {
        Self::new()
    }

    pub fn device_info(&self) -> String {
        self.info.clone()
    }

    pub fn optimal_batch_size(&self) -> usize {
        32768
    }

    pub fn process_batch(
        &self,
        ciphertext: &[u8],
        passphrases: &[String],
    ) -> Result<Option<(usize, String, String)>> {
        if passphrases.is_empty() {
            return Ok(None);
        }
        let batch_size = passphrases.len();
        if batch_size > 65536 {
            bail!("[-] Batch size {} exceeds maximum of 65536", batch_size);
        }
        let start_time = Instant::now();

        // Flatten passphrases
        let mut flat_passphrases = Vec::new();
        let mut offsets = Vec::new();
        let mut lengths = Vec::new();
        for pass in passphrases {
            let lower = pass.to_lowercase();
            let current_len = flat_passphrases.len();
            if current_len > u32::MAX as usize {
                bail!("[!] Passphrase buffer overflow");
            }
            offsets.push(current_len as u32);
            lengths.push(lower.len() as u32);
            flat_passphrases.extend_from_slice(lower.as_bytes());
        }

        // ================================================================
        // DEBUG-Step 0: CPU-side input data
        // ================================================================
        if dbg_on() {
            println!("[DBG] === process_batch: batch_size={} ===", batch_size);
            println!("[DBG] pass[0]='{}' pass[1]='{}'",
                     passphrases[0],
                     if batch_size > 1 { passphrases[1].as_str() } else { "-" });
            println!("[DBG] offsets[0..2]={:?} lengths[0..2]={:?}",
                     &offsets[..2.min(batch_size)], &lengths[..2.min(batch_size)]);
            println!("[DBG] flat_pass[0..40]={}", hex(&flat_passphrases[..40.min(flat_passphrases.len())]));
        }

        // create buffer
        let ct_buffer = self.device.new_buffer_with_data(
            ciphertext.as_ptr() as *const _,
            ciphertext.len() as u64,
            MTLResourceOptions::StorageModeShared,
        );
        let ct_len: u32 = ciphertext.len() as u32;
        let ct_len_buffer = self.device.new_buffer_with_data(
            &ct_len as *const u32 as *const _,
            mem::size_of::<u32>() as u64,
            MTLResourceOptions::StorageModeShared,
        );
        let pass_buffer = self.device.new_buffer_with_data(
            flat_passphrases.as_ptr() as *const _,
            flat_passphrases.len() as u64,
            MTLResourceOptions::StorageModeShared,
        );
        let offset_buffer = self.device.new_buffer_with_data(
            offsets.as_ptr() as *const _,
            (offsets.len() * mem::size_of::<u32>()) as u64,
            MTLResourceOptions::StorageModeShared,
        );
        let length_buffer = self.device.new_buffer_with_data(
            lengths.as_ptr() as *const _,
            (lengths.len() * mem::size_of::<u32>()) as u64,
            MTLResourceOptions::StorageModeShared,
        );
        let salt: [u8; 8] = if ciphertext.len() >= 16 {
            let mut s = [0u8; 8];
            s.copy_from_slice(&ciphertext[8..16]);
            s
        } else {
            [0; 8]
        };
        let salt_buffer = self.device.new_buffer_with_data(
            salt.as_ptr() as *const _,
            8,
            MTLResourceOptions::StorageModeShared,
        );

        // DEBUG: Prefill `derived_keys` with 0xEE (Write verification!)
        let derived_keys_buffer = if dbg_on() {
            let fill = vec![0xEEu8; batch_size * 144];
            self.device.new_buffer_with_data(
                fill.as_ptr() as *const _,
                fill.len() as u64,
                MTLResourceOptions::StorageModeShared,
            )
        } else {
            self.device.new_buffer(
                batch_size as u64 * 144,
                MTLResourceOptions::StorageModeShared,
            )
        };

        let plaintexts_buffer = self.device.new_buffer(
            batch_size as u64 * MAX_CT_LEN,
            MTLResourceOptions::StorageModeShared,
        );
        let plain_lengths_buffer = self.device.new_buffer(
            batch_size as u64 * mem::size_of::<u32>() as u64,
            MTLResourceOptions::StorageModeShared,
        );
        let results: Vec<u32> = vec![0xFFFFFFFF; batch_size];
        let result_buffer = self.device.new_buffer_with_data(
            results.as_ptr() as *const _,
            (batch_size * mem::size_of::<u32>()) as u64,
            MTLResourceOptions::StorageModeShared,
        );
        let output_data_size = batch_size * OUTPUT_MAX_LEN as usize;
        let output_buffer = self.device.new_buffer(
            output_data_size as u64,
            MTLResourceOptions::StorageModeShared,
        );
        let output_len_buffer = self.device.new_buffer(
            (batch_size * mem::size_of::<u32>()) as u64,
            MTLResourceOptions::StorageModeShared,
        );
        let batch_size_u32 = batch_size as u32;
        let batch_size_buffer = self.device.new_buffer_with_data(
            &batch_size_u32 as *const u32 as *const _,
            mem::size_of::<u32>() as u64,
            MTLResourceOptions::StorageModeShared,
        );

        // ================================================================
        // DEBUG-Step 1: Readback Upload-Buffer
        // ================================================================
        if dbg_on() {
            unsafe {
                println!("[DBG] READBACK pass_buf[0..40] = {}", hex(&peek_bytes(&pass_buffer, 40.min(flat_passphrases.len()))));
                println!("[DBG] READBACK offset[0..2]={:?} length[0..2]={:?}",
                         peek_u32(&offset_buffer, 2.min(batch_size)),
                         peek_u32(&length_buffer, 2.min(batch_size)));
                println!("[DBG] READBACK salt={}", hex(&peek_bytes(&salt_buffer, 8)));
                println!("[DBG] READBACK batch_size_buf={:?}", peek_u32(&batch_size_buffer, 1));
                println!("[DBG] READBACK ct_len_buf={:?}", peek_u32(&ct_len_buffer, 1));
            }
        }

        let threads_per_group = 256u64;
        let num_groups = ((batch_size as u64 + threads_per_group - 1) / threads_per_group).max(1);
        let thread_group_size = MTLSize { width: threads_per_group, height: 1, depth: 1 };
        let thread_groups = MTLSize { width: num_groups, height: 1, depth: 1 };

        if dbg_on() {
            println!("[DBG] dispatch: thread_groups={} x threads_per_group={}", num_groups, threads_per_group);
        }

        // ============================ PASS 1 ============================
        {
            let command_buffer = self.command_queue.new_command_buffer();
            let encoder = command_buffer.new_compute_command_encoder();
            encoder.set_compute_pipeline_state(&self.pipeline_derive_keys);
            encoder.set_buffer(0, Some(&pass_buffer), 0);
            encoder.set_buffer(1, Some(&offset_buffer), 0);
            encoder.set_buffer(2, Some(&length_buffer), 0);
            encoder.set_buffer(3, Some(&salt_buffer), 0);
            encoder.set_buffer(4, Some(&derived_keys_buffer), 0);
            encoder.set_buffer(5, Some(&batch_size_buffer), 0);
            encoder.dispatch_thread_groups(thread_groups, thread_group_size);
            encoder.end_encoding();
            command_buffer.commit();
            command_buffer.wait_until_completed();
            if command_buffer.status() != MTLCommandBufferStatus::Completed {
                bail!("[-] Pass 1 failed: {:?}", command_buffer.status());
            }
        }

        // ================================================================
        // DEBUG-Step 2: Did Pass 1 write? (0xEE = NOT written!)
        // ================================================================
        if dbg_on() {
            unsafe {
                let d = peek_bytes(&derived_keys_buffer, 144);
                println!("[DBG] PASS1 done in {:?}. derived[0..144]:", start_time.elapsed());
                println!("[DBG]   {}", hex(&d));
                if d.iter().all(|&b| b == 0xEE) {
                    println!("[DBG]   [-] BUFFER STILL 0xEE -> KERNEL DID NOT WRITE!");
                    println!("[DBG]      => early return (batch_size/len wrong) or wrong Kernel in metallib!");
                } else if d.iter().all(|&b| b == 0x00) {
                    println!("[DBG]   [-] BUFFER COMPLETELY ZERO -> Kernel writes zeros (impossible) => Buffer object bound incorrectly?");
                } else {
                    let nz = count_nonzero(&d);
                    println!("[DBG]   [+] Kernel wrote ({} nonzero bytes) -> compare with ref.js DERIVED!", nz);
                }
            }
        }

        // ============================ PASS 2 ============================
        {
            let command_buffer = self.command_queue.new_command_buffer();
            let encoder = command_buffer.new_compute_command_encoder();
            encoder.set_compute_pipeline_state(&self.pipeline_decrypt);
            encoder.set_buffer(0, Some(&ct_buffer), 0);
            encoder.set_buffer(1, Some(&ct_len_buffer), 0);
            encoder.set_buffer(2, Some(&derived_keys_buffer), 0);
            encoder.set_buffer(3, Some(&plaintexts_buffer), 0);
            encoder.set_buffer(4, Some(&plain_lengths_buffer), 0);
            encoder.set_buffer(5, Some(&batch_size_buffer), 0);
            encoder.dispatch_thread_groups(thread_groups, thread_group_size);
            encoder.end_encoding();
            command_buffer.commit();
            command_buffer.wait_until_completed();
            if command_buffer.status() != MTLCommandBufferStatus::Completed {
                bail!("Pass 2 failed: {:?}", command_buffer.status());
            }
        }

        // ================================================================
        // DEBUG-Step 3: Decrypt-Results
        // ================================================================
        if dbg_on() {
            unsafe {
                let lens = peek_u32(&plain_lengths_buffer, batch_size.min(8));
                println!("[DBG] PASS2 done. plain_lengths[0..{}]={:?}", lens.len(), lens);

                // Alle Slots mit Länge > 0 anzeigen
                let mut found_any = false;
                for (i, &len) in lens.iter().enumerate() {
                    if len > 0 {
                        found_any = true;
                        let base = i * MAX_CT_LEN as usize;
                        let slice = peek_bytes(&plaintexts_buffer, base + len as usize);
                        let plaintext = &slice[base..];

                        println!("[DBG]   Slot {} (len={}):", i, len);
                        println!("[DBG]     Hex: {}", hex(plaintext));

                        // Versuchen als UTF-8 darzustellen
                        if let Ok(text) = std::str::from_utf8(plaintext) {
                            let preview = if text.len() > 100 {
                                format!("{}...", &text[..100])
                            } else {
                                text.to_string()
                            };
                            println!("[DBG]     Text: {}", preview);
                        } else {
                            println!("[DBG]     Text: [not UTF-8]");
                        }
                    }
                }

                if !found_any {
                    println!("[DBG]   [-] All lengths 0 -> PKCS7 padding fails -> derived key/IV incorrect");
                } else {
                    println!("[DBG]   [+] {} plaintext(s) decrypted!", lens.iter().filter(|&&l| l > 0).count());
                }
            }
        }

        // ============================ PASS 3 ============================
        {
            let command_buffer = self.command_queue.new_command_buffer();
            let encoder = command_buffer.new_compute_command_encoder();
            encoder.set_compute_pipeline_state(&self.pipeline_postprocess);
            encoder.set_buffer(0, Some(&plaintexts_buffer), 0);
            encoder.set_buffer(1, Some(&plain_lengths_buffer), 0);
            encoder.set_buffer(2, Some(&result_buffer), 0);
            encoder.set_buffer(3, Some(&output_buffer), 0);
            encoder.set_buffer(4, Some(&output_len_buffer), 0);
            encoder.set_buffer(5, Some(&batch_size_buffer), 0);
            encoder.dispatch_thread_groups(thread_groups, thread_group_size);
            encoder.end_encoding();
            command_buffer.commit();
            command_buffer.wait_until_completed();
            if command_buffer.status() != MTLCommandBufferStatus::Completed {
                bail!("Pass 3 failed: {:?}", command_buffer.status());
            }
        }

        // ================================================================
        // DEBUG-Step 4: Marker/Output
        // ================================================================
        if dbg_on() {
            unsafe {
                println!("[DBG] PASS3 done. results[0..{}]={:?}", 4.min(batch_size), peek_u32(&result_buffer, 4.min(batch_size)));
                println!("[DBG]   output_len[0..{}]={:?}", 4.min(batch_size), peek_u32(&output_len_buffer, 4.min(batch_size)));
                println!("[DBG]   output[0..64]={}", hex(&peek_bytes(&output_buffer, 64.min(output_data_size))));
            }
        }

        let result_ptr = result_buffer.contents() as *const u32;
        let results_slice = unsafe { std::slice::from_raw_parts(result_ptr, batch_size) };
        let output_ptr = output_buffer.contents() as *const u8;
        let output_slice = unsafe { std::slice::from_raw_parts(output_ptr, output_data_size) };
        let output_len_ptr = output_len_buffer.contents() as *const u32;
        let output_len_slice = unsafe { std::slice::from_raw_parts(output_len_ptr, batch_size) };

        for (idx, &result) in results_slice.iter().enumerate() {
            if result == 1 {
                let output_len = output_len_slice[idx] as usize;
                let start = idx * OUTPUT_MAX_LEN as usize;
                let end = start + output_len.min(OUTPUT_MAX_LEN as usize);
                let decrypted = String::from_utf8_lossy(&output_slice[start..end]).to_string();
                return Ok(Some((idx, passphrases[idx].clone(), decrypted)));
            }
        }
        Ok(None)
    }
}