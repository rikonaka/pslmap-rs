/// port scanning
use pistol::PistolLogger;
use pistol::PistolRunner;
use pistol::Target;
use pistol::scan::PortReport;
use pistol::scan::PortStatus;
use pistol::tcp_ack_scan;
use pistol::tcp_connect_scan;
use pistol::tcp_fin_scan;
use pistol::tcp_idle_scan;
use pistol::tcp_maimon_scan;
use pistol::tcp_null_scan;
use pistol::tcp_syn_scan;
use pistol::tcp_window_scan;
use pistol::tcp_xmas_scan;
use pistol::udp_scan;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;
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
    zombie_ipv4: Option<Ipv4Addr>, // tcp idle scan use only
    zombie_port: Option<u16>,      // tcp idle scan use only
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

    let protocol_tcp = "tcp";
    let protocol_udp = "udp";

    let (ret, protocol) = match ps_method {
        PortScanningMethod::TcpSyn => {
            let ret = tcp_syn_scan(
                targets,
                num_threads,
                src_addr,
                src_port,
                timeout,
                max_attempts,
            )
            .expect("tcp syn scan failed");
            (ret, protocol_tcp)
        }
        PortScanningMethod::TcpConnect => {
            let ret = tcp_connect_scan(
                targets,
                num_threads,
                src_addr,
                src_port,
                timeout,
                max_attempts,
            )
            .expect("tcp connect scan failed");
            (ret, protocol_tcp)
        }
        PortScanningMethod::TcpFin => {
            let ret = tcp_fin_scan(
                targets,
                num_threads,
                src_addr,
                src_port,
                timeout,
                max_attempts,
            )
            .expect("tcp fin scan failed");
            (ret, protocol_tcp)
        }
        PortScanningMethod::TcpNull => {
            let ret = tcp_null_scan(
                targets,
                num_threads,
                src_addr,
                src_port,
                timeout,
                max_attempts,
            )
            .expect("tcp null scan failed");
            (ret, protocol_tcp)
        }
        PortScanningMethod::TcpXmas => {
            let ret = tcp_xmas_scan(
                targets,
                num_threads,
                src_addr,
                src_port,
                timeout,
                max_attempts,
            )
            .expect("tcp xmas scan failed");
            (ret, protocol_tcp)
        }
        PortScanningMethod::TcpAck => {
            let ret = tcp_ack_scan(
                targets,
                num_threads,
                src_addr,
                src_port,
                timeout,
                max_attempts,
            )
            .expect("tcp ack scan failed");
            (ret, protocol_tcp)
        }
        PortScanningMethod::TcpWindow => {
            let ret = tcp_window_scan(
                targets,
                num_threads,
                src_addr,
                src_port,
                timeout,
                max_attempts,
            )
            .expect("tcp window scan failed");
            (ret, protocol_tcp)
        }
        PortScanningMethod::TcpMaimon => {
            let ret = tcp_maimon_scan(
                targets,
                num_threads,
                src_addr,
                src_port,
                timeout,
                max_attempts,
            )
            .expect("tcp maimon scan failed");
            (ret, protocol_tcp)
        }
        PortScanningMethod::Udp => {
            let ret = udp_scan(
                targets,
                num_threads,
                src_addr,
                src_port,
                timeout,
                max_attempts,
            )
            .expect("udp scan failed");
            (ret, protocol_udp)
        }
        PortScanningMethod::TcpIdle => {
            let ret = tcp_idle_scan(
                targets,
                num_threads,
                src_addr,
                src_port,
                zombie_ipv4,
                zombie_port,
                timeout,
                max_attempts,
            )
            .expect("tcp idle scan failed");
            (ret, protocol_tcp)
        }
    };

    // sorted
    let mut btm: BTreeMap<IpAddr, BTreeMap<u16, PortReport>> = BTreeMap::new();
    for report in ret.port_reports {
        if let Some(btm_port) = btm.get_mut(&report.addr) {
            btm_port.insert(report.port, report.clone());
        } else {
            let mut btm_port = BTreeMap::new();
            btm_port.insert(report.port, report.clone());
            btm.insert(report.addr, btm_port);
        }
    }

    let mut hosts_up = 0;
    let mut info = Vec::new();
    for (addr, report) in btm {
        for (port, report) in report {
            match report.status {
                PortStatus::Open => {
                    hosts_up += 1;
                }
                _ => (),
            }
            let line = format!(
                "{}:{}/{} -> {} ({:.2}s)",
                addr,
                port,
                protocol,
                report.status,
                report.cost.as_secs_f64()
            );
            info.push(line);
        }
    }

    let info = info.join("\n");
    let tail = format!(
        "pslmap done: {} ip addresses ({} ports up) scanned in {:.2} seconds",
        targets.len(),
        hosts_up,
        start.elapsed().as_secs_f64()
    );
    InfoShow::print(&info, &tail);
}
