/// host discovery
use pistol::PistolLogger;
use pistol::PistolRunner;
use pistol::Target;
use pistol::icmp_address_mask_ping;
use pistol::icmp_echo_ping;
use pistol::icmp_timestamp_ping;
use pistol::mac_scan;
use pistol::ping::PingStatus;
use pistol::tcp_ack_ping;
use pistol::tcp_syn_ping;
use pistol::udp_ping;
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;
use std::time::Instant;

use crate::InfoShow;

/// Nmap Doc (https://nmap.org/book/man-host-discovery.html):
/// The default host discovery done with -sn consists of an ICMP echo request,
/// TCP SYN to port 443, TCP ACK to port 80, and an ICMP timestamp request by default.
/// When executed by an unprivileged user, only SYN packets are sent (using a connect call) to ports 80 and 443
/// on the target. When a privileged user tries to scan targets on a local ethernet network,
/// ARP requests are used unless --send-ip was specified.
#[derive(Debug, Clone, Copy, PartialEq)]
enum HostDiscoveryStatus {
    Up,
    Down,
}

impl fmt::Display for HostDiscoveryStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            HostDiscoveryStatus::Up => "up",
            HostDiscoveryStatus::Down => "down",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum HostDiscoveryMethod {
    IcmpEcho,
    IcmpTimestamp,
    IcmpAddressMask,
    TcpSyn,
    TcpAck,
    Udp,
    Mac,
}

pub fn host_discovery(
    targets: &[Target],
    hd_method: HostDiscoveryMethod,
    log_level: PistolLogger,
    timeout: f64,
    num_threads: usize,
) {
    match hd_method {
        HostDiscoveryMethod::Mac => host_discovery_by_mac(targets, log_level, timeout, num_threads),
        _ => host_discovery_by_ping(targets, hd_method, log_level, timeout, num_threads),
    }
}

fn host_discovery_by_ping(
    targets: &[Target],
    hd_method: HostDiscoveryMethod,
    log_level: PistolLogger,
    timeout: f64,
    num_threads: usize,
) {
    let start = Instant::now();

    let _pr = PistolRunner::init(log_level, None, None).expect("init pistol runner failed");

    let num_threads = Some(num_threads);
    let src_addr = None;
    let src_port = None;
    let max_attempts = 2;
    let timeout = Some(Duration::from_secs_f64(timeout));

    let ret = match hd_method {
        HostDiscoveryMethod::IcmpEcho => {
            let ret = icmp_echo_ping(
                &targets,
                num_threads,
                src_addr,
                src_port,
                timeout,
                max_attempts,
            )
            .expect("icmp echo ping failed");
            ret
        }
        HostDiscoveryMethod::IcmpTimestamp => {
            let ret = icmp_timestamp_ping(
                &targets,
                num_threads,
                src_addr,
                src_port,
                timeout,
                max_attempts,
            )
            .expect("icmp timestamp ping failed");
            ret
        }
        HostDiscoveryMethod::IcmpAddressMask => {
            let ret = icmp_address_mask_ping(
                &targets,
                num_threads,
                src_addr,
                src_port,
                timeout,
                max_attempts,
            )
            .expect("icmp address mask ping failed");
            ret
        }
        HostDiscoveryMethod::TcpSyn => {
            let ret = tcp_syn_ping(
                &targets,
                num_threads,
                src_addr,
                src_port,
                timeout,
                max_attempts,
            )
            .expect("tcp syn ping failed");
            ret
        }
        HostDiscoveryMethod::TcpAck => {
            let ret = tcp_ack_ping(
                &targets,
                num_threads,
                src_addr,
                src_port,
                timeout,
                max_attempts,
            )
            .expect("tcp ack ping failed");
            ret
        }
        HostDiscoveryMethod::Udp => {
            let ret = udp_ping(
                &targets,
                num_threads,
                src_addr,
                src_port,
                timeout,
                max_attempts,
            )
            .expect("udps ping failed");
            ret
        }
        HostDiscoveryMethod::Mac => unreachable!(),
    };

    // sorted
    let mut btm = BTreeMap::new();
    for ping in ret.ping_reports {
        btm.insert(ping.addr, ping.clone());
    }

    let mut hosts_up = 0;
    let mut hosts_not_up = 0;
    let mut info = Vec::new();
    for (addr, ping) in btm {
        let new_status = match ping.status {
            PingStatus::Up => {
                hosts_up += 1;
                HostDiscoveryStatus::Up
            }
            _ => {
                hosts_not_up += 1;
                HostDiscoveryStatus::Down
            }
        };
        if new_status == HostDiscoveryStatus::Up {
            let line = format!(
                "{} -> {} ({:.2}s)",
                addr,
                new_status,
                ping.cost.as_secs_f64()
            );
            info.push(line);
        }
    }

    if hosts_not_up > 0 {
        let line = format!(
            "other {} hosts -> {}",
            hosts_not_up,
            HostDiscoveryStatus::Down
        );
        info.push(line);
    }

    let info = info.join("\n");
    let tail = format!(
        "pslmap done: {} ip addresses ({} hosts up) scanned in {:.2} seconds",
        targets.len(),
        hosts_up,
        start.elapsed().as_secs_f64()
    );
    InfoShow::print(&info, &tail);
}

fn host_discovery_by_mac(
    targets: &[Target],
    log_level: PistolLogger,
    timeout: f64,
    num_threads: usize,
) {
    let start = Instant::now();

    let _pr = PistolRunner::init(log_level, None, None).expect("init pistol runner failed");

    let num_threads = Some(num_threads);
    let src_addr = None;
    let max_attempts = 2;
    let timeout = Some(Duration::from_secs_f64(timeout));
    let ret =
        mac_scan(&targets, num_threads, src_addr, timeout, max_attempts).expect("mac scan failed");

    // sorted
    let mut all_ips = Vec::new();
    for target in targets {
        all_ips.push(target.addr);
    }
    let mut btm = BTreeMap::new();
    for mr in ret.mac_reports {
        btm.insert(mr.addr, mr.clone());
    }

    let mut hosts_up = 0;
    let mut hosts_not_up = 0;
    let mut info = Vec::new();
    for (addr, mr) in btm {
        match mr.mac {
            Some(mac) => {
                hosts_up += 1;
                let line = format!(
                    "{} -> {} ({:.2}s) ({}) ({})",
                    addr,
                    HostDiscoveryStatus::Up,
                    mr.rtt.as_secs_f64(),
                    mac,
                    mr.ouis,
                );
                info.push(line);
            }
            _ => hosts_not_up += 1,
        };
    }

    if hosts_not_up > 0 {
        let line = format!(
            "other {} hosts -> {}",
            hosts_not_up,
            HostDiscoveryStatus::Down
        );
        info.push(line);
    }

    let info = info.join("\n");
    let tail = format!(
        "pslmap done: {} ip addresses ({} hosts up) scanned in {:.2} seconds",
        targets.len(),
        hosts_up,
        start.elapsed().as_secs_f64()
    );
    InfoShow::print(&info, &tail);
}
