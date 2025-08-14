/// remote os detection
use pistol::PistolLogger;
use pistol::PistolRunner;
use pistol::Target;
use pistol::os::OsDetect;
use pistol::os_detect;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;
use std::time::Instant;

use crate::InfoShow;

pub fn os_detection(targets: &[Target], top_k: usize, log_level: PistolLogger, timeout: f64) {
    let start = Instant::now();

    let _pr = PistolRunner::init(log_level, None, None).expect("init pistol runner failed");

    let num_threads = None;
    let src_addr = None;
    let timeout = Some(Duration::from_secs_f64(timeout));

    let ret = os_detect(targets, num_threads, src_addr, top_k, timeout).expect("os detect failed");
    println!("{}", ret);

    // sorted
    let mut btm: BTreeMap<IpAddr, OsDetect> = BTreeMap::new();
    for report in ret.os_detects {
        btm.insert(report.addr(), report.clone());
    }

    let mut info = Vec::new();
    for (addr, detect) in btm {
        let line = match detect {
            OsDetect::V4(x) => {
                let names_vec: Vec<String> = x.detects.iter().map(|x| x.name.clone()).collect();
                let cpe_vec: Vec<String> = x.detects.iter().map(|x| x.cpe.join(",")).collect();
                let line = format!(
                    "{} -> {} {} ({:.2}s)",
                    addr,
                    names_vec.join("|"),
                    cpe_vec.join("|"),
                    x.cost.as_secs_f64(),
                );
                line
            }
            OsDetect::V6(x) => {
                let names_vec: Vec<String> = x.detects.iter().map(|x| x.name.clone()).collect();
                let cpe_vec: Vec<String> = x.detects.iter().map(|x| x.cpe.clone()).collect();
                let line = format!(
                    "{} -> {} {} ({:.2}s)",
                    addr,
                    names_vec.join("|"),
                    cpe_vec.join("|"),
                    x.cost.as_secs_f64(),
                );
                line
            }
        };
        info.push(line);
    }

    let info = info.join("\n");
    let tail = format!(
        "pslmap done: scanned in {:.2} seconds",
        start.elapsed().as_secs_f64()
    );
    InfoShow::print(&info, &tail);
}
