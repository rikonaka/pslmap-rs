/// port scanning
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

#[derive(Debug, Clone, Copy)]
pub enum PortScanningMethod {
    TcpSyn,
    TcpConnect,
    TcpFin,
    TcpNull,
    TcpXmas,
    TcpAck,
    TcpWindow,
    TcpMaimon,
    Udp,
    TcpIdle,
}

pub fn port_scanning(
    targets: &[Target],
    ps_method: PortScanningMethod,
    log_level: PistolLogger,
    timeout: f64,
) {
    let start = Instant::now();

    let _pr = PistolRunner::init(log_level, None, None).expect("init pistol runner failed");

    let num_threads = None;
    let src_addr = None;
    let src_port = None;
    let max_attempts = 2;
    let timeout = Some(Duration::from_secs_f64(timeout));

    let ret = match ps_method {
        HostDiscoveryPingMethod::IcmpEcho => {
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
        HostDiscoveryPingMethod::IcmpTimestamp => {
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
        HostDiscoveryPingMethod::IcmpAddressMask => {
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
        HostDiscoveryPingMethod::TcpSyn => {
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
        HostDiscoveryPingMethod::TcpAck => {
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
        HostDiscoveryPingMethod::Udp => {
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
    };

    // sorted
    let mut btm = BTreeMap::new();
    for ping in ret.ping_reports {
        btm.insert(ping.addr, ping.clone());
    }

    let mut hosts_up = 0;
    let mut info = Vec::new();
    for (addr, ping) in btm {
        let new_status = match ping.status {
            PingStatus::Up => {
                hosts_up += 1;
                HostDiscoveryStatus::Up
            }
            _ => HostDiscoveryStatus::Down,
        };
        let line = format!(
            "{} -> {} ({:.2}s)",
            addr,
            new_status,
            ping.cost.as_secs_f64()
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
