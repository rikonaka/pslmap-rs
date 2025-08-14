use chrono::DateTime;
use chrono::Local;
use clap::Parser;
use clap::Subcommand;
use pistol::PistolLogger;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;

mod hd;
mod od;
mod ps;
mod sd;
mod tp;

use hd::HostDiscoveryMethod;
use hd::host_discovery;
use od::os_detection;
use ps::PortScanningMethod;
use ps::port_scanning;
use tp::TargetParser;

#[derive(Subcommand, Debug)]
enum ToolsSubcommand {
    /// Perform host discovery.
    HD {
        /// Perform host discovery using ICMP Echo Ping (same as the ping command).
        #[arg(short = '1', long = "p1", action, default_value_t = false)]
        ping1: bool,
        /// Perform host discovery using ICMP Timestamp Ping (useful when the target's firewall blocks icmp packets).
        #[arg(short = '2', long = "p2", action, default_value_t = false)]
        ping2: bool,
        /// Perform host discovery using ICMP Address Mask Ping (useful when the target's firewall blocks icmp packets).
        #[arg(short = '3', long = "p3", action, default_value_t = false)]
        ping3: bool,
        /// Perform host discovery using TCP SYN Ping (default target port is 80).
        #[arg(short, long, action, default_value_t = false)]
        syn: bool,
        /// Perform host discovery using TCP ACK Ping (default target port is 80).
        #[arg(short, long, action, default_value_t = false)]
        ack: bool,
        /// Perform host discovery using UDP Ping (default target port is 125).
        #[arg(short, long, action, default_value_t = false)]
        udp: bool,
        /// Perform host discovery using ARP (IPv4) or NDP_NS (IPv6) (this works well when the target machine are on the same subnet).
        #[arg(short, long, action, default_value_t = false)]
        mac: bool,
    },
    /// Perform port scanning.
    PS {
        /// Perform port scanning using TCP SYN scan.
        #[arg(short, long, action, default_value_t = false)]
        syn: bool,
        /// Perform port scanning using TCP Connect scan.
        #[arg(short, long, action, default_value_t = false)]
        connect: bool,
        /// Perform port scanning using TCP FIN scan.
        #[arg(short, long, action, default_value_t = false)]
        fin: bool,
        /// Perform port scanning using TCP Null scan.
        #[arg(short, long, action, default_value_t = false)]
        null: bool,
        /// Perform port scanning using TCP Xmas scan.
        #[arg(short, long, action, default_value_t = false)]
        xmas: bool,
        /// Perform port scanning using TCP ACK scan.
        #[arg(short, long, action, default_value_t = false)]
        ack: bool,
        /// Perform port scanning using TCP Window scan.
        #[arg(short, long, action, default_value_t = false)]
        window: bool,
        /// Perform port scanning using TCP Maimon scan.
        #[arg(short, long, action, default_value_t = false)]
        maimon: bool,
        /// Perform port scanning using UDP scan.
        #[arg(short, long, action, default_value_t = false)]
        udp: bool,
        /// Perform port scanning using TCP Idle scan.
        #[command(subcommand)]
        idle: Option<IdleSubcommand>,
    },
    /// Perform remote os detection.
    OD {
        /// Return only the top_k results.
        #[arg(short, long, default_value_t = 3)]
        top_k: usize,
        /// Set the open_tcp_port parameter.
        #[arg(short = '1', long)]
        open_tcp_port: u16,
        /// Set the close_tcp_port parameter.
        #[arg(short = '2', long)]
        close_tcp_port: u16,
        /// Set the close_udp_port parameter.
        #[arg(short = '3', long)]
        close_udp_port: u16,
    },
}

#[derive(Subcommand, Debug)]
enum IdleSubcommand {
    IDLE {
        /// TCP Idle scan zommbie IPv4 address.
        #[arg(short, long)]
        zombie_ipv4: Ipv4Addr,
        /// TCP Idle scan zommbie IPv4 port.
        #[arg(short, long)]
        zombie_port: u16,
    },
}

/// Nmap rust version.
#[derive(Parser, Debug)]
#[command(author = "RikoNaka", version, about, long_about = None)]
struct Args {
    /// Input target
    #[arg(short, long)]
    target: Option<String>,

    /// Input from list of hosts/networks (same as nmap -iL option)
    #[arg(short, long)]
    filename: Option<String>,

    /// Specified ports
    #[arg(short, long)]
    ports: Option<String>,

    #[command(subcommand)]
    tools: ToolsSubcommand,

    /// Timeout
    #[arg(long, default_value_t = 1.0)]
    timeout: f64,

    /// Display log level (debug, warn, info and none)
    #[arg(short, long, default_value = "none")]
    log: String,

    /// Set the IPv6 address to have the highest priority (this means that when the target is a domain name, the program will first use the IPv6 address as the target address, it does not affect the scanning of using the IP address)
    #[arg(short = '6', long, action, default_value_t = false)]
    ipv6: bool,

    /// Set the IPv4 address to have the highest priority (same as above)
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

fn log_level_parser(log: &str) -> PistolLogger {
    let log = log.to_lowercase();
    match log.as_str() {
        "none" => PistolLogger::None,
        "debug" => PistolLogger::Debug,
        "warn" => PistolLogger::Warn,
        "info" => PistolLogger::Info,
        _ => PistolLogger::None,
    }
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
    if let Some(target) = target {
        let t = TargetParser::target_from_input(&target, ports);
        targets.extend(t);
    } else if let Some(filename) = filename {
        let t = TargetParser::target_from_file(&filename, ports);
        targets.extend(t);
    } else {
        panic!("please set target first");
    }

    if targets.len() == 0 {
        panic!("unable to parse the target");
    }

    let timeout = args.timeout;
    let log_level = log_level_parser(&args.log);

    match args.tools {
        ToolsSubcommand::HD {
            ping1,
            ping2,
            ping3,
            mac,
            syn,
            ack,
            udp,
        } => {
            let hd_method = if ping1 {
                HostDiscoveryMethod::IcmpEcho
            } else if ping2 {
                HostDiscoveryMethod::IcmpTimestamp
            } else if ping3 {
                HostDiscoveryMethod::IcmpAddressMask
            } else if syn {
                HostDiscoveryMethod::TcpSyn
            } else if ack {
                HostDiscoveryMethod::TcpAck
            } else if udp {
                HostDiscoveryMethod::Udp
            } else if mac {
                HostDiscoveryMethod::Mac
            } else {
                HostDiscoveryMethod::Mac
            };
            host_discovery(&targets, hd_method, log_level, timeout);
        }
        ToolsSubcommand::PS {
            syn,
            connect,
            fin,
            null,
            xmas,
            ack,
            window,
            maimon,
            udp,
            idle,
        } => {
            let (ps_method, zombie_ipv4, zombie_port) = if syn {
                (PortScanningMethod::TcpSyn, None, None)
            } else if connect {
                (PortScanningMethod::TcpConnect, None, None)
            } else if fin {
                (PortScanningMethod::TcpFin, None, None)
            } else if null {
                (PortScanningMethod::TcpNull, None, None)
            } else if xmas {
                (PortScanningMethod::TcpXmas, None, None)
            } else if ack {
                (PortScanningMethod::TcpAck, None, None)
            } else if window {
                (PortScanningMethod::TcpWindow, None, None)
            } else if maimon {
                (PortScanningMethod::TcpMaimon, None, None)
            } else if let Some(idle) = idle {
                match idle {
                    IdleSubcommand::IDLE {
                        zombie_ipv4,
                        zombie_port,
                    } => (
                        PortScanningMethod::TcpIdle,
                        Some(zombie_ipv4),
                        Some(zombie_port),
                    ),
                }
            } else if udp {
                (PortScanningMethod::Udp, None, None)
            } else {
                (PortScanningMethod::TcpSyn, None, None)
            };
            port_scanning(
                &targets,
                ps_method,
                zombie_ipv4,
                zombie_port,
                log_level,
                timeout,
            );
        }
        ToolsSubcommand::OD {
            top_k,
            open_tcp_port,
            close_tcp_port,
            close_udp_port,
        } => {
            for t in &mut targets {
                t.ports = vec![open_tcp_port, close_tcp_port, close_udp_port];
            }
            os_detection(&targets, top_k, log_level, timeout)
        }
    }
}
