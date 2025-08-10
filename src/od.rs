/// remote os detection
use pistol::PistolLogger;
use pistol::PistolRunner;
use pistol::Target;
use pistol::os::OsDetect;
use pistol::os_detect;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::time::Duration;
use std::time::Instant;

pub fn os_detection(targets: &[Target], top_k: usize, log_level: PistolLogger, timeout: f64) {
    let start = Instant::now();

    let _pr = PistolRunner::init(log_level, None, None).expect("init pistol runner failed");

    let num_threads = None;
    let src_addr = None;
    let src_port = None;
    let max_attempts = 2;
    let timeout = Some(Duration::from_secs_f64(timeout));

    // do port scan first

    let ret = os_detect(targets, num_threads, src_addr, top_k, timeout).expect("os detect failed");

    // sorted
    let mut btm: BTreeMap<IpAddr, OsDetect> = BTreeMap::new();
    for report in ret.os_detects {
        btm.insert(report.addr(), report.clone());
    }

    let mut hosts_up = 0;
    let mut info = Vec::new();
    for (addr, report) in btm {
        for (port, report) in report {
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
