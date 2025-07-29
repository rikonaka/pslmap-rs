use clap::ArgAction;
use clap::Parser;
use pistol::PistolLogger;
use pistol::PistolRunner;
use pistol::Target;
use pistol::icmp_ping;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;
use subnetwork::Ipv4Pool;
use subnetwork::Ipv6Pool;

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

fn target_parser(target: &str) -> Vec<IpAddr> {
    let mut is_ipv4 = true;
    let mut is_ipv6 = true;
    let mut is_subnet = false;

    for c in target.chars() {
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

    if is_ipv4 && !is_ipv6 {
        if is_subnet {
            let pool = Ipv4Pool::from_str(target)
                .expect(&format!("can not convert target {} to Ipv4Pool", target));
            let last = pool.len();
            let mut all_ips = Vec::new();
            for (i, ip) in pool.into_iter().enumerate() {
                if i == 0 || (last > 0 && i == last - 1) {
                    continue;
                } else {
                    all_ips.push(ip.into());
                }
            }
            all_ips
        } else {
            let ip = Ipv4Addr::from_str(target)
                .expect(&format!("can not convert target {} to Ipv4Addr", target));
            vec![ip.into()]
        }
    } else if !is_ipv4 && is_ipv6 {
        if is_subnet {
            let pool = Ipv6Pool::from_str(target)
                .expect(&format!("can not convert target {} to Ipv6Pool", target));
            let last = pool.len();
            let mut all_ips = Vec::new();
            for (i, ip) in pool.into_iter().enumerate() {
                if i == 0 || (last > 0 && i == last - 1) {
                    continue;
                } else {
                    all_ips.push(ip.into());
                }
            }
            all_ips
        } else {
            let ip = Ipv6Addr::from_str(target)
                .expect(&format!("can not convert target {} to Ipv6Addr", target));
            vec![ip.into()]
        }
    } else {
        // just panic as soon as possible
        panic!("can not convert target {} to IpAddr", target);
    }
}

fn target_from_file(filename: &str) -> Vec<IpAddr> {
    let fp = File::open(filename).expect(&format!("can not open file [{}]", filename));
    let reader = BufReader::new(fp);

    let mut ret = Vec::new();
    for line in reader.lines() {
        let line = line.expect("can not read line");
        let targets = target_parser(&line);
        ret.extend(targets);
    }
    ret
}

fn target_from_input(target: &str) -> Vec<IpAddr> {
    target_parser(target)
}

fn ping_scan(targets: &[IpAddr], timeout: f64) {
    let _pr =
        PistolRunner::init(PistolLogger::None, None, None).expect("init pistol runner failed");

    let mut pistol_targets = Vec::new();
    for &ip in targets {
        let t = Target::new(ip, None);
        pistol_targets.push(t);
    }

    println!("{}", targets.len());

    let num_threads = None;
    let src_addr = None;
    let src_port = None;
    // let timeout = ;
    let max_attempts = 2;
    let timeout = Some(Duration::from_secs_f64(timeout));
    let ret = icmp_ping(
        &pistol_targets,
        num_threads,
        src_addr,
        src_port,
        timeout,
        max_attempts,
    )
    .expect("icmp ping failed");
    println!("{}", ret);
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

    /// Ping Scan - disable port scan (same as nmap -sn option)
    #[arg(long, action(ArgAction::SetTrue))]
    pingscan: bool,

    /// Timeout
    #[arg(long, default_value_t = 1.0)]
    timeout: f64,

    /// The udp listen port
    #[arg(short, long, default_value = "")]
    udp: String,

    /// When receiving data, return the data set in this parameter
    #[arg(short, long, default_value = "null", default_missing_value = "", num_args(0..2))]
    need_return: String,
}

fn main() {
    let args = Args::parse();
    let mut targets = Vec::new();
    if args.target.len() > 0 {
        let t = target_from_input(&args.target);
        targets.extend(t);
    } else if args.filename.len() > 0 {
        let t = target_from_file(&args.filename);
        targets.extend(t);
    } else {
        panic!("please set target first");
    }

    if targets.len() == 0 {
        panic!("unable to parse the target");
    }

    if args.pingscan {
        ping_scan(&targets, args.timeout);
    }
}
