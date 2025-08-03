use pistol::Target;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::LazyLock;

use crate::IPV6_FIRST;

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

pub struct TargetParser;

impl TargetParser {
    fn parser(addrs: &str, ports: &str) -> Vec<Target> {
        let ports_parser = || -> Option<Vec<u16>> {
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
        };

        let mut is_ipv4 = true;
        let mut is_ipv6 = true;
        let mut is_subnet = false;

        let mut addr_judge = || {
            for c in addrs.chars() {
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
        };

        addr_judge();
        let ports = ports_parser();

        let addr_parser = || -> Vec<Target> {
            if is_ipv4 && !is_ipv6 {
                if is_subnet {
                    let targets = Target::from_subnet(addrs, ports)
                        .expect(&format!("can not convert subnet {} to targets", addrs));
                    targets
                } else {
                    let ip = Ipv4Addr::from_str(addrs)
                        .expect(&format!("can not convert target {} to Ipv4Addr", addrs));
                    let target = Target::new(ip.into(), ports);
                    vec![target]
                }
            } else if !is_ipv4 && is_ipv6 {
                if is_subnet {
                    let targets = Target::from_subnet(addrs, ports)
                        .expect(&format!("can not convert subnet {} to targets", addrs));
                    targets
                } else {
                    let ip = Ipv6Addr::from_str(addrs)
                        .expect(&format!("can not convert target {} to Ipv6Addr", addrs));
                    let target = Target::new(ip.into(), ports);
                    vec![target]
                }
            } else {
                // parser as domain name
                let ipv6_first = IPV6_FIRST.lock().expect("try lock IPV6_FIRST failed");
                let targets = if *ipv6_first {
                    Target::from_domain6(addrs, ports)
                        .expect(&format!("convert domain {} to target failed", addrs))
                } else {
                    Target::from_domain(addrs, ports)
                        .expect(&format!("convert domain {} to target failed", addrs))
                };
                targets
            }
        };

        addr_parser()
    }
    pub fn target_from_file(filename: &str, target_ports: &str) -> Vec<Target> {
        let fp = File::open(filename).expect(&format!("can not open file [{}]", filename));
        let reader = BufReader::new(fp);

        let mut ret = Vec::new();
        for line in reader.lines() {
            let line = line.expect("can not read line");
            // ignore the port here
            let targets = TargetParser::parser(&line, target_ports);
            ret.extend(targets);
        }
        ret
    }
    pub fn target_from_input(target_addr: &str, target_ports: &str) -> Vec<Target> {
        TargetParser::parser(target_addr, target_ports)
    }
}
