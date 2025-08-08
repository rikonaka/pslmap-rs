use chrono::DateTime;
use chrono::Local;
use clap::Parser;
use clap::Subcommand;
use pistol::PistolLogger;
use pistol::PistolRunner;
use pistol::Target;
use pistol::icmp_echo_ping;
use pistol::mac_scan;
use pistol::ping::PingStatus;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

mod target;

use target::TargetParser;

#[derive(Subcommand, Debug)]
enum Tools {
    /// Perform host discovery
    HD {
        /// Host discovery by using ping scan
        #[arg(long, action, default_value_t = false)]
        ping: bool,
        /// Host discovery by using arp scan or ndp_ns scan
        #[arg(long, action, default_value_t = false)]
        mac: bool,
    },
}

/// Nmap rust version.
#[derive(Parser, Debug)]
#[command(author = "RikoNaka", version, about, long_about = None)]
struct Args {
    /// Input target
    #[arg(short, long, default_value = "")]
    target: String,

    /// Input from list of hosts/networks (same as nmap -iL option)
    #[arg(short, long, default_value = "")]
    filename: String,

    /// Specified ports
    #[arg(short, long, default_value = "")]
    ports: String,

    #[command(subcommand)]
    tools: Tools,

    /// Timeout
    #[arg(long, default_value_t = 1.0)]
    timeout: f64,

    /// Set the IPv6 address to have the highest priority (this means that when the target is a domain name, the program will first use the IPv6 address as the target address, it does not affect the scanning of using the IP address)
    #[arg(short = '6', long, action, default_value_t = false)]
    ipv6: bool,

    /// Set the IPv4 address to have the highest priority
    #[arg(short = '4', long, action, default_value_t = false)]
    ipv4: bool,
}

static IPV6_FIRST: LazyLock<Arc<Mutex<bool>>> = LazyLock::new(|| Arc::new(Mutex::new(false)));

struct InfoShow;

impl InfoShow {
    fn print(info: &str, tail: &str) {
        let app = env!("CARGO_PKG_NAME");
        let version = env!("CARGO_PKG_VERSION");
        let now: DateTime<Local> = Local::now();
        let formatted_time = now.format("%Y-%m-%d %H:%M:%S").to_string();
        println!("starting {} {} at {}", app, version, formatted_time,);
        println!("{}", info);
        println!("{}", tail);
    }
}

/// Nmap Doc (https://nmap.org/book/man-host-discovery.html):
/// The default host discovery done with -sn consists of an ICMP echo request,
/// TCP SYN to port 443, TCP ACK to port 80, and an ICMP timestamp request by default.
/// When executed by an unprivileged user, only SYN packets are sent (using a connect call) to ports 80 and 443
/// on the target. When a privileged user tries to scan targets on a local ethernet network,
/// ARP requests are used unless --send-ip was specified.
#[derive(Debug, Clone, Copy)]
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

/// Same as the ping command in the system.
fn host_discovery_echo_ping_scan(targets: &[Target], timeout: f64) {
    let start = Instant::now();

    let _pr =
        PistolRunner::init(PistolLogger::None, None, None).expect("init pistol runner failed");

    let num_threads = None;
    let src_addr = None;
    let src_port = None;
    let max_attempts = 2;
    let timeout = Some(Duration::from_secs_f64(timeout));
    let ret = icmp_echo_ping(
        &targets,
        num_threads,
        src_addr,
        src_port,
        timeout,
        max_attempts,
    )
    .expect("icmp ping failed");

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

/// When the target address is local, you can use arp scan or ndp ns scan.
fn host_discovery_mac_scan(targets: &[Target], timeout: f64) {
    let start = Instant::now();

    let _pr =
        PistolRunner::init(PistolLogger::None, None, None).expect("init pistol runner failed");

    let num_threads = None;
    let src_addr = None;
    let max_attempts = 2;
    let timeout = Some(Duration::from_secs_f64(timeout));
    let ret = mac_scan(&targets, num_threads, src_addr, timeout, max_attempts).expect("mac failed");

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
    let mut info = Vec::new();
    for (addr, mr) in btm {
        let new_status = match mr.mac {
            Some(mac) => {
                hosts_up += 1;
                format!("{}({})", HostDiscoveryStatus::Up, mac)
            }
            _ => format!("{}", HostDiscoveryStatus::Down),
        };
        let line = format!("{} -> {}", addr, new_status);
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

fn main() {
    let args = Args::parse();
    let mut targets = Vec::new();

    if args.ipv6 {
        let mut ipv6_first = IPV6_FIRST.lock().expect("try lock IPV6_FIRST failed");
        (*ipv6_first) = true;
    } else if args.ipv4 {
        let mut ipv6_first = IPV6_FIRST.lock().expect("try lock IPV6_FIRST failed");
        (*ipv6_first) = false;
    }

    let ports = args.ports;
    let target = args.target;
    let filename = args.filename;
    if target.len() > 0 {
        let t = TargetParser::target_from_input(&target, &ports);
        targets.extend(t);
    } else if filename.len() > 0 {
        let t = TargetParser::target_from_file(&filename, &ports);
        targets.extend(t);
    } else {
        panic!("please set target first");
    }

    if targets.len() == 0 {
        panic!("unable to parse the target");
    }

    let timeout = args.timeout;

    match args.tools {
        Tools::HD { ping, mac } => {
            if ping {
                host_discovery_echo_ping_scan(&targets, timeout);
            } else if mac {
                host_discovery_mac_scan(&targets, timeout);
            }
        }
    }
}
