use std::sync::{Arc, Mutex};

pub fn enhanced_intrusion_detection(access_counter: &Arc<Mutex<u64>>) -> Result<(), String> {
    
    detect_debugger_presence()?;
    detect_analysis_environment()?;
    detect_code_injection()?;

    let mut counter = access_counter.lock()
        .map_err(|_| "Erreur de verrouillage critique")?;

    *counter += 1;
    let access_rate = *counter;

    if access_rate > 2000 {
        return Err("Détection d'attaque par force brute".into());
    }

    if detect_high_cpu_usage() {
        eprintln!("Avertissement: Charge système élevée détectée - surveillance renforcée");

    }

    perform_deep_system_surveillance()?;

    Ok(())
}

pub fn detect_high_cpu_usage() -> bool {

    if let Ok(loadavg) = std::fs::read_to_string("/proc/loadavg") {
        if let Some(load1_str) = loadavg.split_whitespace().next() {
            if let Ok(load1) = load1_str.parse::<f64>() {

                let cpu_count = num_cpus::get() as f64;
                let suspicious_threshold = cpu_count * 0.8; // 80% de charge

                if load1 > suspicious_threshold {
                    eprintln!("Avertissement: Charge CPU élevée détectée: {:.2}", load1);
                    return true;
                }
            }
        }
    }
    false
}

pub fn detect_debugger_presence() -> Result<(), String> {

    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("TracerPid:") {
                let tracer_pid: i32 = line.split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                if tracer_pid != 0 {
                    eprintln!("Avertissement: Processus tracé détecté (PID: {})", tracer_pid);

                    return Ok(());
                }
            }
        }
    }

    if let Ok(ppid_comm) = std::fs::read_to_string("/proc/self/stat") {
        if let Some(ppid_part) = ppid_comm.split_whitespace().nth(3) {
            if let Ok(ppid) = ppid_part.parse::<i32>() {
                if let Ok(parent_comm) = std::fs::read_to_string(format!("/proc/{}/comm", ppid)) {
                    let suspicious_parents = ["gdb", "strace", "ltrace"];
                    for suspect in &suspicious_parents {
                        if parent_comm.trim().contains(suspect) {
                            eprintln!("Avertissement: Processus parent suspect: {}", parent_comm.trim());

                        }
                    }
                }
            }
        }
    }

    Ok(())
}


pub fn detect_analysis_environment() -> Result<(), String> {

    let suspicious_processes = [
        "gdb", "strace", "ltrace", "wireshark", "tcpdump",
        "ida", "x64dbg", "ollydbg", "windbg", "radare2"
    ];

    if let Ok(processes) = std::fs::read_to_string("/proc/self/comm") {
        for suspect in &suspicious_processes {
            if processes.to_lowercase().contains(suspect) {
                return Err(format!("Outil d'analyse détecté: {}", suspect));
            }
        }
    }


    if let Ok(output) = std::process::Command::new("dmesg").output() {
        let dmesg_str = String::from_utf8_lossy(&output.stdout).to_lowercase();
        let hypervisor_indicators = [
            "kvmkvmkvm", "microsoft hv", "vmwarevmware", 
            "xenvmmxenvmm", "vboxvboxvbox"
        ];

        for indicator in &hypervisor_indicators {
            if dmesg_str.contains(indicator) {
                return Err("Environnement virtualisé détecté".into());
            }
        }
    }

    Ok(())
}


pub fn detect_code_injection() -> Result<(), String> {

    let critical_function_ptr = detect_high_cpu_usage as *const () as usize;

    unsafe {
        let first_bytes = std::slice::from_raw_parts(
            critical_function_ptr as *const u8, 8
        );

        // Détection de jump/call suspects (0xE9, 0xE8, 0xFF)
        if first_bytes[0] == 0xE9 || first_bytes[0] == 0xE8 || first_bytes[0] == 0xFF {
            return Err("Hook de fonction détecté".into());
        }
    }

    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        let suspicious_libs = [
            "frida", "substrate", "inject", "pin", "dynamorio"
        ];

        for line in maps.lines() {
            for suspect in &suspicious_libs {
                if line.to_lowercase().contains(suspect) {
                    return Err(format!("Bibliothèque d'injection détectée: {}", suspect));
                }
            }
        }
    }

    Ok(())
}

pub fn perform_deep_system_surveillance() -> Result<(), String> {

    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        analyze_memory_usage(&meminfo)?;
    }

    scan_background_processes()?;

    monitor_network_connections()?;
    
    check_system_integrity()?;

    detect_behavioral_anomalies()?;

    Ok(())
}

pub fn analyze_memory_usage(meminfo: &str) -> Result<(), String> {
    let mut mem_total = 0u64;
    let mut mem_available = 0u64;

    for line in meminfo.lines() {
        if line.starts_with("MemTotal:") {
            if let Some(value) = line.split_whitespace().nth(1) {
                mem_total = value.parse().unwrap_or(0);
            }
        } else if line.starts_with("MemAvailable:") {
            if let Some(value) = line.split_whitespace().nth(1) {
                mem_available = value.parse().unwrap_or(0);
            }
        }
    }

    if mem_total > 0 {
        let usage_percent = ((mem_total - mem_available) as f64 / mem_total as f64) * 100.0;
        if usage_percent > 90.0 {
            eprintln!("Avertissement: Utilisation mémoire critique: {:.1}%", usage_percent);
        }
    }

    Ok(())
}

pub fn scan_background_processes() -> Result<(), String> {

    let advanced_suspicious_tools = [
        "volatility", "rekall", "sleuthkit", "autopsy", "binwalk",
        "foremost", "scalpel", "photorec", "testdisk", "dd_rescue",
        "dcfldd", "dc3dd", "ewf-tools", "afflib", "chkrootkit",
        "rkhunter", "maldet", "yara", "clamav", "john",
        "hashcat", "aircrack", "kismet", "nmap", "masscan",
        "zap", "burpsuite", "metasploit", "sqlmap", "nikto"
    ];


    if let Ok(proc_dir) = std::fs::read_dir("/proc") {
        for entry in proc_dir.flatten() {
            if let Ok(file_type) = entry.file_type() {
                if file_type.is_dir() {
                    if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                        let comm_path = format!("/proc/{}/comm", pid);
                        if let Ok(comm) = std::fs::read_to_string(&comm_path) {
                            let process_name = comm.trim().to_lowercase();
                            for &suspect in &advanced_suspicious_tools {
                                if process_name.contains(suspect) {
                                    eprintln!("Alerte: Processus suspect détecté: {} (PID: {})", process_name, pid);

                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}


pub fn monitor_network_connections() -> Result<(), String> {

    if let Ok(tcp_connections) = std::fs::read_to_string("/proc/net/tcp") {
        let mut suspicious_connections = 0;

        for line in tcp_connections.lines().skip(1) { 
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {

                if parts[3] == "01" {
                    suspicious_connections += 1;
                }
            }
        }

        if suspicious_connections > 50 {
            eprintln!("Avertissement: Nombre élevé de connexions réseau: {}", suspicious_connections);
        }
    }

    Ok(())
}


pub fn check_system_integrity() -> Result<(), String> {

    let critical_files = [
        "/proc/version",
        "/proc/cpuinfo", 
        "/proc/meminfo"
    ];

    for &file_path in &critical_files {
        if !std::path::Path::new(file_path).exists() {
            return Err(format!("Fichier système critique manquant: {}", file_path));
        }
    }

    Ok(())
}


pub fn detect_behavioral_anomalies() -> Result<(), String> {

    let start = std::time::Instant::now();
    let _cpu_count = num_cpus::get();
    let response_time = start.elapsed();

    if response_time > std::time::Duration::from_millis(100) {
        eprintln!("Avertissement: Temps de réponse système anormalement élevé: {:?}", response_time);
    }

    Ok(())
}
