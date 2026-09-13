use chrono::Utc;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("Scan error: {0}")]
    ScanError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Timeout")]
    Timeout,
}

type Result<T> = std::result::Result<T, NetworkError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub target: String,
    pub ports: Vec<u16>,
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub scan_type: ScanType,
    pub service_detection: bool,
    pub os_fingerprint: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            ports: vec![21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017],
            timeout_ms: 2000,
            concurrency: 100,
            scan_type: ScanType::Syn,
            service_detection: true,
            os_fingerprint: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanType {
    Connect,
    Syn,
    Udp,
    Fin,
    Null,
    Xmas,
}

impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanType::Connect => write!(f, "connect"),
            ScanType::Syn => write!(f, "syn"),
            ScanType::Udp => write!(f, "udp"),
            ScanType::Fin => write!(f, "fin"),
            ScanType::Null => write!(f, "null"),
            ScanType::Xmas => write!(f, "xmastree"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: String,
    pub target: String,
    pub scan_type: ScanType,
    pub start_time: String,
    pub end_time: Option<String>,
    pub duration_ms: u64,
    pub hosts: Vec<HostResult>,
    pub status: ScanStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    pub ip: String,
    pub hostname: Option<String>,
    pub state: HostState,
    pub ports: Vec<PortResult>,
    pub os_fingerprint: Option<OsFingerprint>,
    pub scan_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HostState {
    Up,
    Down,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub service: Option<ServiceInfo>,
    pub banner: Option<String>,
    pub response_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unfiltered,
    OpenFiltered,
    ClosedFiltered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub version: Option<String>,
    pub product: Option<String>,
    pub extra_info: Option<String>,
    pub cpe: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsFingerprint {
    pub os_name: String,
    pub accuracy: u8,
    pub cpe: Option<String>,
    pub os_class: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResult {
    pub domain: String,
    pub records: Vec<DnsRecord>,
    pub mx_records: Vec<String>,
    pub ns_records: Vec<String>,
    pub txt_records: Vec<String>,
    pub spf: Option<String>,
    pub dkim: Option<String>,
    pub dmarc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisResult {
    pub domain: String,
    pub registrar: Option<String>,
    pub creation_date: Option<String>,
    pub expiration_date: Option<String>,
    pub name_servers: Vec<String>,
    pub status: Vec<String>,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslInfo {
    pub hostname: String,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub serial_number: Option<String>,
    pub fingerprint: Option<String>,
    pub san: Vec<String>,
    pub protocol_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub key_exchange: Option<String>,
    pub vulnerabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainResult {
    pub domain: String,
    pub subdomains: Vec<SubdomainEntry>,
    pub total_found: usize,
    pub scan_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainEntry {
    pub subdomain: String,
    pub ip: Option<String>,
    pub record_type: String,
}

pub struct NetworkScanner;

impl NetworkScanner {
    pub async fn scan_ports(config: ScanConfig) -> Result<ScanResult> {
        let scan_id = format!("netscan_{}", Utc::now().timestamp_millis());
        let start = std::time::Instant::now();
        let start_time = Utc::now().to_rfc3339();

        let addrs = Self::resolve_target(&config.target).await?;
        let mut hosts = Vec::new();

        for addr in addrs {
            let host_result = Self::scan_host(&addr, &config).await;
            hosts.push(host_result);
        }

        let duration = start.elapsed().as_millis() as u64;

        Ok(ScanResult {
            scan_id,
            target: config.target,
            scan_type: config.scan_type,
            start_time,
            end_time: Some(Utc::now().to_rfc3339()),
            duration_ms: duration,
            hosts,
            status: ScanStatus::Completed,
        })
    }

    async fn resolve_target(target: &str) -> Result<Vec<IpAddr>> {
        if let Ok(ip) = target.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        if let Ok(network) = target.parse::<IpNetwork>() {
            return Ok(network.iter().take(256).collect());
        }

        let addrs: Vec<IpAddr> = format!("{}:80", target)
            .to_socket_addrs()
            .map_err(|e| NetworkError::ParseError(e.to_string()))?
            .map(|s| s.ip())
            .collect();

        if addrs.is_empty() {
            return Err(NetworkError::ParseError(format!("Could not resolve: {}", target)));
        }

        Ok(addrs)
    }

    async fn scan_host(ip: &IpAddr, config: &ScanConfig) -> HostResult {
        let start = std::time::Instant::now();
        let timeout_dur = Duration::from_millis(config.timeout_ms);

        let mut ports = Vec::new();
        let chunks: Vec<&[u16]> = config.ports.chunks(config.concurrency).collect();

        for chunk in chunks {
            let futures: Vec<_> = chunk.iter().map(|&port| {
                let addr = SocketAddr::new(*ip, port);
                async move {
                    let result = Self::check_port(addr, timeout_dur, config.service_detection).await;
                    result
                }
            }).collect();

            let results = futures::future::join_all(futures).await;
            for result in results {
                if let Ok(port_result) = result {
                    ports.push(port_result);
                }
            }
        }

        ports.sort_by_key(|p| p.port);

        let hostname = Self::reverse_dns(ip).await;

        HostResult {
            ip: ip.to_string(),
            hostname,
            state: if ports.iter().any(|p| p.state == PortState::Open) {
                HostState::Up
            } else {
                HostState::Unknown
            },
            ports,
            os_fingerprint: None,
            scan_time_ms: start.elapsed().as_millis() as u64,
        }
    }

    async fn check_port(
        addr: SocketAddr,
        timeout_dur: Duration,
        grab_banner: bool,
    ) -> Result<PortResult> {
        let start = std::time::Instant::now();

        let connect_result = timeout(timeout_dur, TcpStream::connect(addr)).await;

        match connect_result {
            Ok(Ok(stream)) => {
                let mut banner = None;
                let service = Self::detect_service(addr.port());

                if grab_banner {
                    banner = Self::grab_banner(stream).await;
                }

                Ok(PortResult {
                    port: addr.port(),
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service,
                    banner,
                    response_time_ms: start.elapsed().as_millis() as u64,
                })
            }
            Ok(Err(_)) => {
                Ok(PortResult {
                    port: addr.port(),
                    protocol: Protocol::Tcp,
                    state: PortState::Closed,
                    service: None,
                    banner: None,
                    response_time_ms: start.elapsed().as_millis() as u64,
                })
            }
            Err(_) => {
                Ok(PortResult {
                    port: addr.port(),
                    protocol: Protocol::Tcp,
                    state: PortState::Filtered,
                    service: None,
                    banner: None,
                    response_time_ms: timeout_dur.as_millis() as u64,
                })
            }
        }
    }

    fn detect_service(port: u16) -> Option<ServiceInfo> {
        let services: HashMap<u16, (&str, &str)> = [
            (21, ("ftp", "File Transfer Protocol")),
            (22, ("ssh", "Secure Shell")),
            (23, ("telnet", "Telnet")),
            (25, ("smtp", "Simple Mail Transfer Protocol")),
            (53, ("dns", "Domain Name System")),
            (80, ("http", "Hypertext Transfer Protocol")),
            (110, ("pop3", "Post Office Protocol v3")),
            (135, ("msrpc", "Microsoft RPC")),
            (139, ("netbios-ssn", "NetBIOS Session Service")),
            (143, ("imap", "Internet Message Access Protocol")),
            (443, ("https", "HTTP over TLS/SSL")),
            (445, ("microsoft-ds", "Microsoft SMB")),
            (993, ("imaps", "IMAP over TLS")),
            (995, ("pop3s", "POP3 over TLS")),
            (1433, ("mssql", "Microsoft SQL Server")),
            (1521, ("oracle", "Oracle Database")),
            (3306, ("mysql", "MySQL Database")),
            (3389, ("rdp", "Remote Desktop Protocol")),
            (5432, ("postgresql", "PostgreSQL Database")),
            (5900, ("vnc", "Virtual Network Computing")),
            (6379, ("redis", "Redis Key-Value Store")),
            (8080, ("http-proxy", "HTTP Proxy")),
            (8443, ("https-alt", "HTTPS Alternate")),
            (27017, ("mongodb", "MongoDB Database")),
        ].iter().cloned().collect();

        services.get(&port).map(|(name, desc)| ServiceInfo {
            name: name.to_string(),
            version: None,
            product: Some(desc.to_string()),
            extra_info: None,
            cpe: None,
        })
    }

    async fn grab_banner(_stream: TcpStream) -> Option<String> {
        None
    }

    async fn reverse_dns(ip: &IpAddr) -> Option<String> {
        use trust_dns_resolver::config::*;
        use trust_dns_resolver::AsyncResolver;

        let resolver = AsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        let response = resolver.reverse_lookup(*ip).await.ok()?;

        response.iter().next().map(|name| name.to_string())
    }

    pub async fn enumerate_subdomains(domain: &str, wordlist: Option<Vec<String>>) -> Result<SubdomainResult> {
        let start = std::time::Instant::now();

        let default_wordlist = vec![
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
            "webdisk", "admin", "blog", "dev", "test", "stage", "api", "secure", "vpn",
            "m", "mobile", "shop", "store", "support", "portal", "forum", "bbs", "wiki",
            "docs", "help", "status", "monitor", "git", "gitlab", "jenkins", "ci", "cdn",
            "static", "img", "images", "video", "media", "assets", "files", "download",
            "upload", "backup", "old", "new", "beta", "alpha", "demo", "staging", "prod",
            "internal", "external", "remote", "office", "corp", "auth", "sso", "login",
            "account", "accounts", "user", "users", "my", "app", "apps", "service",
            "services", "ws", "api1", "api2", "v1", "v2", "v3", "graph", "graphql",
        ];

        let words = wordlist.unwrap_or_else(|| default_wordlist.iter().map(|s| s.to_string()).collect());
        let mut subdomains = Vec::new();

        for word in &words {
            let subdomain = format!("{}.{}", word, domain);
            if let Ok(addrs) = format!("{}:80", subdomain).to_socket_addrs() {
                for addr in addrs {
                    subdomains.push(SubdomainEntry {
                        subdomain: subdomain.clone(),
                        ip: Some(addr.ip().to_string()),
                        record_type: "A".to_string(),
                    });
                    break;
                }
            }
        }

        let total = subdomains.len();

        Ok(SubdomainResult {
            domain: domain.to_string(),
            subdomains,
            total_found: total,
            scan_time_ms: start.elapsed().as_millis() as u64,
        })
    }

    pub async fn check_ssl(hostname: &str, port: u16) -> Result<SslInfo> {
        let addr = format!("{}:{}", hostname, port);
        let timeout_dur = Duration::from_secs(5);

        let connect_result = timeout(timeout_dur, TcpStream::connect(&addr)).await;

        match connect_result {
            Ok(Ok(_stream)) => {
                Ok(SslInfo {
                    hostname: hostname.to_string(),
                    issuer: None,
                    subject: None,
                    not_before: None,
                    not_after: None,
                    serial_number: None,
                    fingerprint: None,
                    san: Vec::new(),
                    protocol_version: None,
                    cipher_suite: None,
                    key_exchange: None,
                    vulnerabilities: Vec::new(),
                })
            }
            Ok(Err(e)) => Err(NetworkError::IoError(e)),
            Err(_) => Err(NetworkError::Timeout),
        }
    }

    pub async fn dns_lookup(domain: &str) -> Result<DnsResult> {
        use trust_dns_resolver::config::*;
        use trust_dns_resolver::AsyncResolver;

        let resolver = AsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        let mut records = Vec::new();
        let mut mx_records = Vec::new();
        let mut ns_records = Vec::new();
        let mut txt_records = Vec::new();

        if let Ok(response) = resolver.lookup_ip(domain).await {
            for ip in response.iter() {
                records.push(DnsRecord {
                    name: domain.to_string(),
                    record_type: if ip.is_ipv4() { "A".to_string() } else { "AAAA".to_string() },
                    value: ip.to_string(),
                    ttl: None,
                });
            }
        }

        if let Ok(response) = resolver.mx_lookup(domain).await {
            for mx in response.iter() {
                mx_records.push(format!("{} {}", mx.preference(), mx.exchange()));
            }
        }

        if let Ok(response) = resolver.ns_lookup(domain).await {
            for ns in response.iter() {
                ns_records.push(ns.to_string());
            }
        }

        if let Ok(response) = resolver.txt_lookup(domain).await {
            for txt in response.iter() {
                let txt_bytes: Vec<u8> = txt.iter().flat_map(|s| s.to_vec()).collect();
                let txt_str = String::from_utf8_lossy(&txt_bytes).to_string();
                txt_records.push(txt_str.clone());

                if txt_str.starts_with("v=spf1") {
                    records.push(DnsRecord {
                        name: domain.to_string(),
                        record_type: "SPF".to_string(),
                        value: txt_str,
                        ttl: None,
                    });
                }
            }
        }

        Ok(DnsResult {
            domain: domain.to_string(),
            records,
            mx_records,
            ns_records,
            txt_records,
            spf: None,
            dkim: None,
            dmarc: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_detection() {
        let service = NetworkScanner::detect_service(80);
        assert!(service.is_some());
        assert_eq!(service.unwrap().name, "http");
    }

    #[test]
    fn test_default_ports() {
        let config = ScanConfig::default();
        assert!(config.ports.len() > 20);
        assert!(config.ports.contains(&80));
        assert!(config.ports.contains(&443));
    }
}
