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
                let mut service = Self::detect_service(addr.port());

                if grab_banner {
                    banner = Self::grab_banner(stream, addr).await;
                }

                // A banner often reveals the exact version, which the port map
                // alone cannot know.
                if let Some(svc) = service.as_mut() {
                    if svc.version.is_none() {
                        if let Some(b) = &banner {
                            svc.version = Self::extract_version(svc, b);
                        }
                    }
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

    /// Read a service banner.
    ///
    /// Ports that speak HTTP get a minimal HEAD request first, because those
    /// services stay silent until spoken to; everything else is read passively.
    /// A banner is best-effort: silence is a legitimate result, not an error.
    async fn grab_banner(mut stream: TcpStream, addr: SocketAddr) -> Option<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const BANNER_TIMEOUT: Duration = Duration::from_secs(3);
        const MAX_BANNER: usize = 1024;

        if matches!(addr.port(), 80 | 8080 | 8000 | 8888 | 3000 | 5000) {
            let host = addr.ip();
            let request = format!("HEAD / HTTP/1.0\r\nHost: {}\r\nUser-Agent: siterecorder\r\n\r\n", host);
            if timeout(Duration::from_secs(2), stream.write_all(request.as_bytes()))
                .await
                .is_err()
            {
                return None;
            }
        }

        let mut buf = vec![0u8; MAX_BANNER];
        match timeout(BANNER_TIMEOUT, stream.read(&mut buf)).await {
            Ok(Ok(0)) => None,
            Ok(Ok(n)) => {
                let raw = String::from_utf8_lossy(&buf[..n]).to_string();
                let cleaned: String = raw
                    .lines()
                    .map(|l| l.trim_end_matches('\r'))
                    .collect::<Vec<_>>()
                    .join(" | ");
                let cleaned = cleaned.trim().to_string();
                if cleaned.is_empty() {
                    None
                } else {
                    Some(cleaned.chars().take(MAX_BANNER).collect())
                }
            }
            _ => None,
        }
    }

    /// A plausible product version: at least two dot-separated numeric parts.
    ///
    /// Rejects bare protocol numbers like "1.1" from an HTTP status line.
    fn is_plausible_version(candidate: &str) -> bool {
        let trimmed = candidate.trim_end_matches('.');
        let parts: Vec<&str> = trimmed.split('.').filter(|p| !p.is_empty()).collect();
        parts.len() >= 2
            && trimmed.len() >= 5
            && parts.iter().all(|p| p.chars().next().is_some_and(|c| c.is_ascii_digit()))
    }

    /// Extract a version string that follows the service name in a banner.
    ///
    /// Banners put the product and version in many shapes -- `nginx/1.18.0`,
    /// `OpenSSH_8.9p1`, `MySQL 8.0.32` -- so this searches for the product
    /// name positionally and then reads the version characters that follow,
    /// rather than tokenising on separators that are themselves the delimiter.
    fn extract_version(service: &ServiceInfo, banner: &str) -> Option<String> {
        let needle = service.name.replace(' ', "");
        if needle.is_empty() {
            return None;
        }

        let haystack: Vec<char> = banner.chars().collect();
        let needle_chars: Vec<char> = needle.chars().collect();

        // Case-insensitive search for the product name.
        let mut start: Option<usize> = None;
        if needle_chars.len() <= haystack.len() {
            'outer: for i in 0..=(haystack.len() - needle_chars.len()) {
                for j in 0..needle_chars.len() {
                    if haystack[i + j].to_ascii_lowercase() != needle_chars[j].to_ascii_lowercase() {
                        continue 'outer;
                    }
                }
                start = Some(i + needle_chars.len());
                break;
            }
        }

        if let Some(pos) = start {
            // Skip any separator characters before the version begins.
            let mut i = pos;
            while i < haystack.len() && !haystack[i].is_ascii_alphanumeric() {
                i += 1;
            }
            // Read the version run: alphanumerics and dots (covers "8.9p1").
            let mut version = String::new();
            while i < haystack.len() && (haystack[i].is_ascii_alphanumeric() || haystack[i] == '.') {
                version.push(haystack[i]);
                i += 1;
            }
            let version = version.trim_end_matches('.').to_string();
            // Require a plausible product version, else an HTTP banner yields
            // the protocol version ("HTTP/1.1") as if it were a product version.
            if Self::is_plausible_version(&version) {
                return Some(version);
            }
        }

        // Fall back to the first dotted numeric run anywhere in the banner.
        let mut current = String::new();
        for c in banner.chars() {
            if c.is_ascii_digit() || c == '.' {
                current.push(c);
            } else {
                if Self::is_plausible_version(&current) {
                    return Some(current.trim_end_matches('.').to_string());
                }
                current.clear();
            }
        }
        if Self::is_plausible_version(&current) {
            return Some(current.trim_end_matches('.').to_string());
        }

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

    /// Inspect the TLS service on `hostname:port`.
    ///
    /// Uses the `openssl s_client` CLI rather than linking a TLS stack: the
    /// project already shells out (ffmpeg, ffmpeg screen capture) and this
    /// keeps the dependency footprint small. Returns a typed error when the
    /// binary is unavailable rather than silently reporting an empty result --
    /// an "unknown TLS posture" must never look like a clean scan.
    pub async fn check_ssl(hostname: &str, port: u16) -> Result<SslInfo> {
        let output = tokio::process::Command::new("openssl")
            .args([
                "s_client",
                "-connect",
                &format!("{}:{}", hostname, port),
                "-servername",
                hostname,
                "-showcerts",
            ])
            .stdin(std::process::Stdio::null())
            .output();

        let output = match timeout(Duration::from_secs(10), output).await {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => {
                return Err(NetworkError::ScanError(format!(
                    "could not run openssl: {}. Install OpenSSL to enable TLS inspection.",
                    e
                )))
            }
            Err(_) => return Err(NetworkError::Timeout),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{}\n{}", stdout, stderr);

        if combined.contains("Connection refused") || combined.contains("connect:errno") {
            return Err(NetworkError::ScanError(format!(
                "TCP connection to {}:{} refused",
                hostname, port
            )));
        }

        let cert_pem = Self::extract_first_certificate(&stdout)
            .ok_or_else(|| NetworkError::ScanError("no certificate presented by peer".into()))?;

        let mut info = Self::parse_certificate(&cert_pem)?;
        info.hostname = hostname.to_string();

        // Session parameters. TLS 1.3 and earlier use different output shapes:
        //   TLS 1.3: "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384"
        //   TLS <=1.2: a "Protocol : / Cipher : / Server Temp Key:" block
        // Both must be handled, or a modern host reports no cipher at all.
        if let Some((proto, cipher)) = Self::match_new_line(&combined) {
            info.protocol_version = Some(proto);
            info.cipher_suite = Some(cipher);
        } else {
            info.protocol_version = Self::match_field(&combined, "Protocol  :");
            info.cipher_suite = Self::match_field(&combined, "Cipher    :");
            info.key_exchange = Self::match_field(&combined, "Server Temp Key:");
        }

        if let Some(proto) = &info.protocol_version {
            if proto.contains("TLSv1.0") || proto.contains("SSLv3") {
                info.vulnerabilities
                    .push("Deprecated protocol version in use (TLS 1.0 / SSLv3)".into());
            }
        }

        Ok(info)
    }

    fn extract_first_certificate(pem_dump: &str) -> Option<String> {
        let start = pem_dump.find("-----BEGIN CERTIFICATE-----")?;
        let end = pem_dump[start..].find("-----END CERTIFICATE-----")?;
        Some(pem_dump[start..start + end + "-----END CERTIFICATE-----".len()].to_string())
    }

    fn parse_certificate(pem: &str) -> Result<SslInfo> {
        let issuer = Self::openssl_x509(pem, &["-issuer", "-nameopt", "RFC2253"]);
        let subject = Self::openssl_x509(pem, &["-subject", "-nameopt", "RFC2253"]);
        let not_before = Self::openssl_x509(pem, &["-startdate"]);
        let not_after = Self::openssl_x509(pem, &["-enddate"]);
        let serial = Self::openssl_x509(pem, &["-serial"]);
        let fingerprint = Self::openssl_x509(pem, &["-fingerprint", "-sha256"]);
        let san = Self::openssl_x509(pem, &["-ext", "subjectAltName"]);

        let san_entries = san
            .as_deref()
            .map(|raw| {
                raw.split(',')
                    .map(|part| {
                        part.split(':')
                            .next_back()
                            .unwrap_or("")
                            .trim()
                            .to_string()
                    })
                    .filter(|v| !v.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(SslInfo {
            hostname: String::new(),
            issuer,
            subject,
            not_before,
            not_after,
            serial_number: serial,
            fingerprint,
            san: san_entries,
            protocol_version: None,
            cipher_suite: None,
            key_exchange: None,
            vulnerabilities: Vec::new(),
        })
    }

    /// Synchronous helper used during certificate parsing.
    fn openssl_x509(pem: &str, args: &[&str]) -> Option<String> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let mut child = Command::new("openssl")
            .arg("x509")
            .arg("-noout")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .ok()?;

        // Passing the PEM on stdin keeps it out of the process argument list.
        if let Some(stdin) = child.stdin.as_mut() {
            let _ = stdin.write_all(pem.as_bytes());
        }

        let out = child.wait_with_output().ok()?;
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }

    /// Parse the TLS 1.3 "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384" line.
    ///
    /// Returns (protocol, cipher). TLS 1.3 drops the legacy
    /// "Protocol : / Cipher :" block entirely, so without this a modern host
    /// reports no cipher suite at all.
    fn match_new_line(text: &str) -> Option<(String, String)> {
        let line = text.lines().find(|l| {
            let t = l.trim();
            t.starts_with("New,") && t.contains("TLS") && t.contains("Cipher is")
        })?;

        let parts: Vec<&str> = line.trim().split(',').map(|p| p.trim()).collect();
        if parts.len() < 3 {
            return None;
        }

        let proto = parts[1].to_string();
        let cipher_part = parts[2];
        let cipher = cipher_part
            .strip_prefix("Cipher is ")
            .unwrap_or(cipher_part)
            .trim()
            .to_string();

        if proto.is_empty() || cipher.is_empty() {
            return None;
        }
        Some((proto, cipher))
    }

    /// Pull a whitespace-delimited value following `prefix` from s_client output.
    fn match_field<'a>(text: &'a str, prefix: &str) -> Option<String> {
        text.lines()
            .find(|l| l.trim_start().starts_with(prefix))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
            .filter(|v| !v.is_empty())
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

    fn service_named(name: &str) -> ServiceInfo {
        ServiceInfo {
            name: name.to_string(),
            version: None,
            product: None,
            extra_info: None,
            cpe: None,
        }
    }

    #[test]
    fn extracts_slash_delimited_version() {
        let svc = service_named("nginx");
        assert_eq!(
            NetworkScanner::extract_version(&svc, "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0"),
            Some("1.18.0".to_string())
        );
    }

    #[test]
    fn extracts_underscore_delimited_version() {
        let svc = service_named("OpenSSH");
        let banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4";
        assert_eq!(
            NetworkScanner::extract_version(&svc, banner),
            Some("8.9p1".to_string())
        );
    }

    #[test]
    fn extracts_spaced_version() {
        let svc = service_named("MySQL");
        assert_eq!(
            NetworkScanner::extract_version(&svc, "5.5.68-0ubuntu0.22.04.1"),
            Some("5.5.68".to_string())
        );
    }

    #[test]
    fn no_version_in_banner_yields_none() {
        let svc = service_named("http");
        assert_eq!(NetworkScanner::extract_version(&svc, "HTTP/1.1 400 Bad Request"), None);
    }

    #[test]
    fn empty_banner_yields_none() {
        let svc = service_named("http");
        assert_eq!(NetworkScanner::extract_version(&svc, ""), None);
    }

    #[test]
    fn extracts_certificate_block() {
        let dump = "some noise\n-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\ntrailing";
        let pem = NetworkScanner::extract_first_certificate(dump).unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.ends_with("-----END CERTIFICATE-----"));
    }

    #[test]
    fn missing_certificate_yields_none() {
        assert!(NetworkScanner::extract_first_certificate("no cert here").is_none());
    }

    #[test]
    fn parses_s_client_fields() {
        let text = "    Protocol  : TLSv1.2\n    Cipher    : ECDHE-RSA-AES256-GCM-SHA384\n    Server Temp Key: X25519";
        assert_eq!(
            NetworkScanner::match_field(text, "Protocol  :"),
            Some("TLSv1.2".to_string())
        );
        assert_eq!(
            NetworkScanner::match_field(text, "Cipher    :"),
            Some("ECDHE-RSA-AES256-GCM-SHA384".to_string())
        );
        assert_eq!(
            NetworkScanner::match_field(text, "Server Temp Key:"),
            Some("X25519".to_string())
        );
    }

    #[test]
    fn absent_field_yields_none() {
        assert_eq!(NetworkScanner::match_field("nothing here", "Protocol  :"), None);
    }

    // Regression: TLS 1.3 dropped the legacy "Protocol : / Cipher :" block, so
    // a modern host reported no cipher suite at all until this was handled.

    #[test]
    fn parses_tls13_new_line() {
        let text = "    New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n    Server public key is 256 bit";
        assert_eq!(
            NetworkScanner::match_new_line(text),
            Some((
                "TLSv1.3".to_string(),
                "TLS_AES_256_GCM_SHA384".to_string()
            ))
        );
    }

    #[test]
    fn tls12_output_has_no_new_line() {
        let text = "    Protocol  : TLSv1.2\n    Cipher    : ECDHE-RSA-AES256-GCM-SHA384";
        assert_eq!(NetworkScanner::match_new_line(text), None);
        // ...and the legacy parser still handles it.
        assert_eq!(
            NetworkScanner::match_field(text, "Cipher    :"),
            Some("ECDHE-RSA-AES256-GCM-SHA384".to_string())
        );
    }

    #[test]
    fn malformed_new_line_yields_none() {
        assert_eq!(NetworkScanner::match_new_line("New, TLSv1.3"), None);
        assert_eq!(NetworkScanner::match_new_line("New, , Cipher is X"), None);
    }

    #[test]
    fn certificate_parsing_populates_fields() {
        if which_openssl().is_none() {
            eprintln!("skipping: openssl not on PATH");
            return;
        }
        // Self-signed throwaway cert generated in-process.
        let pem = match signed_test_certificate() {
            Some(p) => p,
            None => {
                eprintln!("skipping: could not generate a test certificate");
                return;
            }
        };

        let info = NetworkScanner::parse_certificate(&pem).unwrap();
        assert!(info.issuer.is_some(), "issuer should parse");
        assert!(info.subject.is_some(), "subject should parse");
        assert!(info.not_before.is_some());
        assert!(info.not_after.is_some());
        assert!(info.serial_number.is_some());
        assert!(info.fingerprint.is_some());
    }

    fn which_openssl() -> Option<std::path::PathBuf> {
        std::process::Command::new("openssl")
            .arg("version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .ok()
            .filter(|s| s.success())
            .map(|_| std::path::PathBuf::from("openssl"))
    }

    /// Generate a throwaway self-signed certificate for parse tests.
    /// Returns a PEM string. Skips (rather than fails) if openssl is absent.
    fn signed_test_certificate() -> Option<String> {
        use std::process::{Command, Stdio};

        let dir = tempfile::tempdir().ok()?;
        let key = dir.path().join("k.pem");
        let cert = dir.path().join("c.pem");

        let out = Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key.to_str()?,
                "-out", cert.to_str()?,
                "-days", "1", "-subj", "/CN=siterecorder-test",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok()?;
        if !out.success() {
            return None;
        }

        // Read before `dir` is dropped, which removes the temp directory.
        let pem = std::fs::read_to_string(&cert).ok()?;
        Some(pem)
    }
}
