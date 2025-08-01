use chrono::DateTime;
use chrono::Local;
use clap::ArgAction;
use clap::Parser;
use pistol::PistolLogger;
use pistol::PistolRunner;
use pistol::Target;
use pistol::icmp_ping;
use pistol::mac_scan;
use pistol::ping::PingStatus;
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

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

    /// Ping Scan - host discovery
    #[arg(long, action(ArgAction::SetTrue), default_value_t = false)]
    pingscan: bool,

    /// Mac Scan - host discovery
    #[arg(long, action(ArgAction::SetTrue), default_value_t = false)]
    macscan: bool,

    /// Timeout
    #[arg(long, default_value_t = 1.0)]
    timeout: f64,

    /// Set the IPv6 address to have the highest priority (this means that when the target is a domain name, the program will first use the IPv6 address as the target address)
    #[arg(long, action(ArgAction::SetTrue), default_value_t = false)]
    ipv6: bool,

    /// The udp listen port
    #[arg(short, long, default_value = "")]
    udp: String,

    /// When receiving data, return the data set in this parameter
    #[arg(short, long, default_value = "null", default_missing_value = "", num_args(0..2))]
    need_return: String,
}

static IPV6_FIRST: LazyLock<Arc<Mutex<bool>>> = LazyLock::new(|| Arc::new(Mutex::new(false)));

static IPV4_IEGAL_CHARS: LazyLock<Arc<Vec<char>>> = LazyLock::new(|| {
    let mut ipv4_legal_chars = Vec::new();
    for c in '0'..='9' {
        ipv4_legal_chars.push(c);
    }
    ipv4_legal_chars.push('.');
    // 192.168.1.1/24
    ipv4_legal_chars.push('/');
    Arc::new(ipv4_legal_chars)
});

static IPV6_IEGAL_CHARS: LazyLock<Arc<Vec<char>>> = LazyLock::new(|| {
    let mut ipv6_legal_chars = Vec::new();
    for c in '0'..='f' {
        ipv6_legal_chars.push(c);
    }
    ipv6_legal_chars.push(':');
    ipv6_legal_chars.push('/');
    Arc::new(ipv6_legal_chars)
});

fn ports_parser(ports: &str) -> Option<Vec<u16>> {
    // 80,81,443-999
    if ports.trim().len() == 0 {
        return None;
    }

    let mut ret = Vec::new();
    let ports_split: Vec<&str> = ports
        .split(",")
        .filter(|x| x.trim().len() == 0)
        .map(|x| x.trim())
        .collect();
    for ps in ports_split {
        if ps.contains("-") {
            let range_split: Vec<&str> = ps
                .split("-")
                .filter(|x| x.trim().len() == 0)
                .map(|x| x.trim())
                .collect();
            if range_split.len() == 2 {
                let start: u16 = range_split[0]
                    .parse()
                    .expect(&format!("convert {} to u16 failed", range_split[0]));
                let end: u16 = range_split[1]
                    .parse()
                    .expect(&format!("convert {} to u16 failed", range_split[1]));
                if start < end {
                    for p in start..=end {
                        ret.push(p);
                    }
                } else {
                    panic!("{}(start) >= {}(end)", start, end);
                }
            }
        } else {
            let p: u16 = ps.parse().expect(&format!("convert {} to u16 failed", ps));
            ret.push(p);
        }
    }
    Some(ret)
}

fn target_parser(target_addr: &str, target_ports: &str) -> Vec<Target> {
    let mut is_ipv4 = true;
    let mut is_ipv6 = true;
    let mut is_subnet = false;

    for c in target_addr.chars() {
        if !IPV4_IEGAL_CHARS.contains(&c) {
            is_ipv4 = false;
        }
        if !IPV6_IEGAL_CHARS.contains(&c) {
            is_ipv6 = false;
        }
        if c == '/' {
            is_subnet = true;
        }
    }

    let ports = ports_parser(target_ports);

    if is_ipv4 && !is_ipv6 {
        if is_subnet {
            let targets = Target::from_subnet(target_addr, ports).expect(&format!(
                "can not convert subnet {} to targets",
                target_addr
            ));
            targets
        } else {
            let ip = Ipv4Addr::from_str(target_addr).expect(&format!(
                "can not convert target {} to Ipv4Addr",
                target_addr
            ));
            let target = Target::new(ip.into(), ports);
            vec![target]
        }
    } else if !is_ipv4 && is_ipv6 {
        if is_subnet {
            let targets = Target::from_subnet(target_addr, ports).expect(&format!(
                "can not convert subnet {} to targets",
                target_addr
            ));
            targets
        } else {
            let ip = Ipv6Addr::from_str(target_addr).expect(&format!(
                "can not convert target {} to Ipv6Addr",
                target_addr
            ));
            let target = Target::new(ip.into(), ports);
            vec![target]
        }
    } else {
        // parser as domain name
        let ipv6_first = IPV6_FIRST.lock().expect("try lock IPV6_FIRST failed");
        let targets = if *ipv6_first {
            Target::from_domain6(target_addr, ports)
                .expect(&format!("convert domain {} to target failed", target_addr))
        } else {
            Target::from_domain(target_addr, ports)
                .expect(&format!("convert domain {} to target failed", target_addr))
        };
        targets
    }
}

fn target_from_file(filename: &str, target_ports: &str) -> Vec<Target> {
    let fp = File::open(filename).expect(&format!("can not open file [{}]", filename));
    let reader = BufReader::new(fp);

    let mut ret = Vec::new();
    for line in reader.lines() {
        let line = line.expect("can not read line");
        // ignore the port here
        let targets = target_parser(&line, target_ports);
        ret.extend(targets);
    }
    ret
}

fn target_from_input(target_addr: &str, target_ports: &str) -> Vec<Target> {
    target_parser(target_addr, target_ports)
}

static REPO_LINK: &str = "https://github.com/rikonaka/pslmap-rs";

struct InfoShow;

impl InfoShow {
    fn print(info: &str, tail: &str) {
        let app = env!("CARGO_PKG_NAME");
        let version = env!("CARGO_PKG_VERSION");
        let now: DateTime<Local> = Local::now();
        let formatted_time = now.format("%Y-%m-%d %H:%M %Z").to_string();
        println!(
            "Starting {} {} ({}) at {}",
            app, version, REPO_LINK, formatted_time,
        );
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
fn host_discovery_ping_scan(targets: &[Target], timeout: f64) {
    let start = Instant::now();

    let _pr =
        PistolRunner::init(PistolLogger::None, None, None).expect("init pistol runner failed");

    let num_threads = None;
    let src_addr = None;
    let src_port = None;
    let max_attempts = 2;
    let timeout = Some(Duration::from_secs_f64(timeout));
    let ret = icmp_ping(
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
        "Nmap done: {} IP addresses ({} hosts up) scanned in {:.2} seconds",
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
        "Nmap done: {} IP addresses ({} hosts up) scanned in {:.2} seconds",
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
    }

    if args.target.len() > 0 {
        let t = target_from_input(&args.target, &args.ports);
        targets.extend(t);
    } else if args.filename.len() > 0 {
        let t = target_from_file(&args.filename, &args.ports);
        targets.extend(t);
    } else {
        panic!("please set target first");
    }

    if targets.len() == 0 {
        panic!("unable to parse the target");
    }

    if args.pingscan {
        host_discovery_ping_scan(&targets, args.timeout);
    } else if args.macscan {
        host_discovery_mac_scan(&targets, args.timeout);
    }
}
