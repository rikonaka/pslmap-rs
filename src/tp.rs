/// target parser
use pistol::Target;
use pistol::dns_query;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::FromStr;
use subnetwork::CrossIpv4Pool;
use subnetwork::CrossIpv6Pool;

use crate::IPV6_FIRST;

// from https://data.iana.org/TLD/tlds-alpha-by-domain.txt (2025-8-8)
fn get_all_tlds() -> Vec<String> {
    let tlds_txt = include_str!("./db/tlds-alpha-by-domain.txt");
    let mut tlds = Vec::new();
    for line in tlds_txt.lines() {
        if !line.starts_with("#") {
            tlds.push(line.to_uppercase());
            tlds.push(line.to_lowercase());
        }
    }
    tlds
}

pub struct TargetParser;

impl TargetParser {
    fn ports_parser(ports: Option<String>) -> Vec<u16> {
        // 80,81,443-999
        if let Some(ports) = ports {
            if ports.trim().len() == 0 {
                return Vec::new();
            }

            let mut ret = Vec::new();
            let mut ports_split = Vec::new();
            if ports.contains(",") {
                let split_ret: Vec<String> = ports
                    .split(",")
                    .filter(|x| x.trim().len() > 0)
                    .map(|x| x.trim().to_string())
                    .collect();
                ports_split.extend(split_ret);
            } else {
                ports_split.push(ports.to_string());
            }

            for ps in ports_split {
                if ps.contains("-") {
                    let range_split: Vec<&str> = ps
                        .split("-")
                        .filter(|x| x.trim().len() > 0)
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
            ret
        } else {
            Vec::new()
        }
    }
    fn parser(addrs: &str, ports: Option<String>) -> Vec<Target> {
        if addrs.trim().len() == 0 {
            return Vec::new();
        }

        // parse ports first
        let ports = Self::ports_parser(ports);

        let addr_parser = |addr_str: &str, ports: Option<Vec<u16>>| -> Vec<Target> {
            let mut targets = Vec::new();
            let domian_guess_split: Vec<&str> = addr_str.split(".").map(|x| x.trim()).collect();
            let tld = if domian_guess_split.len() > 0 {
                Some(domian_guess_split[domian_guess_split.len() - 1])
            } else {
                None
            };

            let all_tlds = get_all_tlds();
            let mut is_domain = false;
            if let Some(tld) = tld {
                if all_tlds.contains(&tld.to_string()) {
                    is_domain = true;
                }
            }

            if !is_domain {
                if addr_str.contains("-") {
                    let split_ret: Vec<&str> = addr_str
                        .split("-")
                        .filter(|x| x.trim().len() > 0)
                        .map(|x| x.trim())
                        .collect();
                    if split_ret.len() == 2 {
                        let start_ip = split_ret[0];
                        let end_ip = split_ret[1];
                        let ret = if start_ip.contains(":") || end_ip.contains(":") {
                            // ipv6
                            let start_ipv6 = Ipv6Addr::from_str(start_ip)
                                .expect(&format!("convert {} to Ipv6Addr failed", start_ip));
                            let end_ipv6 = Ipv6Addr::from_str(end_ip)
                                .expect(&format!("convert {} to Ipv6Addr failed", end_ip));
                            let ips = CrossIpv6Pool::new(start_ipv6, end_ipv6).expect(&format!(
                                "get cross ipv6 pool ({}-{}) failed",
                                start_ipv6, end_ipv6
                            ));
                            let mut ret = Vec::new();
                            for ip in ips {
                                let mut t = Target::new(ip.into(), ports.clone());
                                // set the origin addr info
                                t.origin = Some(addr_str.to_string());
                                ret.push(t);
                            }
                            ret
                        } else {
                            // ipv4
                            let start_ipv4 = Ipv4Addr::from_str(start_ip)
                                .expect(&format!("convert {} to Ipv4Addr failed", start_ip));
                            let end_ipv4 = Ipv4Addr::from_str(end_ip)
                                .expect(&format!("convert {} to Ipv4Addr failed", end_ip));
                            let ips = CrossIpv4Pool::new(start_ipv4, end_ipv4).expect(&format!(
                                "get cross ipv4 pool ({}-{}) failed",
                                start_ipv4, end_ipv4
                            ));
                            let mut ret = Vec::new();
                            for ip in ips {
                                let mut t = Target::new(ip.into(), ports.clone());
                                // set the origin addr info
                                t.origin = Some(addr_str.to_string());
                                ret.push(t);
                            }
                            ret
                        };
                        targets.extend(ret);
                    }
                } else if addr_str.contains("/") {
                    let t = Target::from_subnet(addr_str, ports)
                        .expect(&format!("get subnet target from {} failed", addr_str));
                    targets.extend(t);
                } else {
                    let target = if addr_str.contains(":") {
                        // ipv6
                        let ip = Ipv6Addr::from_str(addrs)
                            .expect(&format!("can not convert target {} to Ipv4Addr", addrs));
                        Target::new(ip.into(), ports)
                    } else {
                        // ipv4
                        let ip = Ipv4Addr::from_str(addrs)
                            .expect(&format!("can not convert target {} to Ipv4Addr", addrs));
                        Target::new(ip.into(), ports)
                    };
                    targets.push(target);
                }
            } else {
                let query_ret =
                    dns_query(addr_str).expect(&format!("dns query {} failed", addr_str));
                let mut ret = Vec::new();
                let ipv6_first = IPV6_FIRST.lock().expect("lock IPV6_FIRST failed");

                for ip in query_ret {
                    match ip {
                        IpAddr::V4(_) => {
                            if !(*ipv6_first) {
                                let mut t = Target::new(ip, ports.clone());
                                t.origin = Some(addr_str.to_string());
                                ret.push(t);
                            }
                        }
                        IpAddr::V6(_) => {
                            if *ipv6_first {
                                let mut t = Target::new(ip, ports.clone());
                                t.origin = Some(addr_str.to_string());
                                ret.push(t);
                            }
                        }
                    }
                }
                targets.extend(ret);
            }
            targets
        };

        let mut targets = Vec::new();
        let mut addrs_split = Vec::new();
        if addrs.contains(",") {
            let split: Vec<String> = addrs
                .split(",")
                .filter(|x| x.trim().len() > 0)
                .map(|x| x.trim().to_string())
                .collect();
            addrs_split.extend(split);
        } else {
            addrs_split.push(addrs.to_string());
        }

        for addr_str in addrs_split {
            let t = addr_parser(&addr_str, Some(ports.clone()));
            targets.extend(t);
        }
        targets
    }
    pub fn target_from_file(filename: &str, target_ports: Option<String>) -> Vec<Target> {
        let fp = File::open(filename).expect(&format!("can not open file [{}]", filename));
        let reader = BufReader::new(fp);

        let mut targets = Vec::new();
        for line in reader.lines() {
            let line = line.expect("can not read line");
            // ignore the port here
            let t = TargetParser::parser(&line, target_ports.clone());
            targets.extend(t);
        }
        targets
    }
    pub fn target_from_input(target_addr: &str, target_ports: Option<String>) -> Vec<Target> {
        TargetParser::parser(target_addr, target_ports)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parser() {
        let test_targets = vec!["192.168.5.5-192.168.5.10", "192.168.5.5/24", "baidu.com"];
        let test_ports = vec!["80", "80-90", "80-90,5432", "80,81,143,443-445"];

        for t in &test_targets {
            for p in &test_ports {
                let ret = TargetParser::target_from_input(t, Some(p.to_string()));
                println!("{:?}", ret);
                println!(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
            }
        }
    }
}
