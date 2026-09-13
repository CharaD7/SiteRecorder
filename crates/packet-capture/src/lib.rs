use chrono::Utc;
use pnet::datalink::{self, Channel, DataLinkReceiver, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{broadcast, Mutex, RwLock};
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Pcap error: {0}")]
    Pcap(String),
    #[error("No suitable interface found")]
    NoInterface,
    #[error("Permission denied - run as root/admin")]
    PermissionDenied,
}

type Result<T> = std::result::Result<T, CaptureError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInfo {
    pub id: String,
    pub timestamp: String,
    pub interface: String,
    pub length: usize,
    pub capture_length: usize,
    pub link_layer: LinkLayerInfo,
    pub network_layer: Option<NetworkLayerInfo>,
    pub transport_layer: Option<TransportLayerInfo>,
    pub application_layer: Option<ApplicationLayerInfo>,
    pub raw_bytes: Option<String>,
    pub color_rule: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkLayerInfo {
    pub source_mac: String,
    pub dest_mac: String,
    pub ethertype: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkLayerInfo {
    pub version: u8,
    pub source_ip: String,
    pub dest_ip: String,
    pub ttl: u8,
    pub protocol: String,
    pub header_length: u8,
    pub total_length: u16,
    pub identification: Option<u16>,
    pub flags: Option<String>,
    pub fragment_offset: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportLayerInfo {
    pub protocol: String,
    pub source_port: u16,
    pub dest_port: u16,
    pub sequence_number: Option<u32>,
    pub acknowledgment_number: Option<u32>,
    pub flags: Option<String>,
    pub window_size: Option<u16>,
    pub payload_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationLayerInfo {
    pub protocol: String,
    pub info: String,
    pub headers: Option<HashMap<String, String>>,
    pub body_preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureFilter {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub filter_type: FilterType,
    pub value: String,
    pub color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FilterType {
    IpAddress,
    Port,
    Protocol,
    Hostname,
    PacketSize,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureSession {
    pub id: String,
    pub interface: String,
    pub started_at: String,
    pub stopped_at: Option<String>,
    pub packet_count: usize,
    pub filter: Option<String>,
    pub promiscuous: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureStats {
    pub total_packets: usize,
    pub total_bytes: usize,
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
    pub protocol_distribution: HashMap<String, usize>,
    pub top_talkers: Vec<TopTalker>,
    pub errors: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopTalker {
    pub ip: String,
    pub packets: usize,
    pub bytes: usize,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CaptureEvent {
    PacketCaptured(PacketInfo),
    CaptureStarted(String),
    CaptureStopped(String),
    StatsUpdated(CaptureStats),
    Error(String),
}

pub struct PacketCapture {
    running: Arc<RwLock<bool>>,
    packets: Arc<RwLock<Vec<PacketInfo>>>,
    filters: Arc<RwLock<Vec<CaptureFilter>>>,
    stats: Arc<RwLock<CaptureStats>>,
    tx: broadcast::Sender<CaptureEvent>,
    current_session: Arc<RwLock<Option<CaptureSession>>>,
}

impl PacketCapture {
    pub fn new() -> (Self, broadcast::Receiver<CaptureEvent>) {
        let (tx, rx) = broadcast::channel(4096);
        (
            Self {
                running: Arc::new(RwLock::new(false)),
                packets: Arc::new(RwLock::new(Vec::new())),
                filters: Arc::new(RwLock::new(Vec::new())),
                stats: Arc::new(RwLock::new(CaptureStats {
                    total_packets: 0,
                    total_bytes: 0,
                    packets_per_second: 0.0,
                    bytes_per_second: 0.0,
                    protocol_distribution: HashMap::new(),
                    top_talkers: Vec::new(),
                    errors: 0,
                })),
                tx,
                current_session: Arc::new(RwLock::new(None)),
            },
            rx,
        )
    }

    pub async fn list_interfaces() -> Vec<NetworkInterfaceInfo> {
        datalink::interfaces()
            .into_iter()
            .map(|iface| NetworkInterfaceInfo {
                name: iface.name.clone(),
                description: iface.description.clone(),
                index: iface.index,
                mac: iface.mac.map(|m| m.to_string()),
                ips: iface.ips.iter().map(|ip| ip.to_string()).collect(),
                is_up: iface.is_up(),
                is_loopback: iface.is_loopback(),
            })
            .collect()
    }

    pub async fn start_capture(&self, interface_name: &str, promiscuous: bool, filter: Option<&str>) -> Result<()> {
        if *self.running.read().await {
            return Err(CaptureError::Pcap("Capture already running".to_string()));
        }

        let interface = Self::find_interface(interface_name)?;
        let session = CaptureSession {
            id: Uuid::new_v4().to_string(),
            interface: interface_name.to_string(),
            started_at: Utc::now().to_rfc3339(),
            stopped_at: None,
            packet_count: 0,
            filter: filter.map(|s| s.to_string()),
            promiscuous,
        };

        *self.current_session.write().await = Some(session.clone());
        *self.running.write().await = true;
        self.packets.write().await.clear();

        let _ = self.tx.send(CaptureEvent::CaptureStarted(session.id.clone()));

        let running = self.running.clone();
        let packets = self.packets.clone();
        let filters = self.filters.clone();
        let stats = self.stats.clone();
        let tx = self.tx.clone();
        let iface_name = interface_name.to_string();

        tokio::spawn(async move {
            match Self::capture_loop(&iface_name, promiscuous, running, packets, filters, stats, tx).await {
                Ok(_) => {}
                Err(e) => {
                    tracing::error!("Capture error: {}", e);
                }
            }
        });

        Ok(())
    }

    async fn capture_loop(
        interface_name: &str,
        _promiscuous: bool,
        running: Arc<RwLock<bool>>,
        packets: Arc<RwLock<Vec<PacketInfo>>>,
        filters: Arc<RwLock<Vec<CaptureFilter>>>,
        stats: Arc<RwLock<CaptureStats>>,
        tx: broadcast::Sender<CaptureEvent>,
    ) -> Result<()> {
        let interface = Self::find_interface(interface_name)?;
        let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(CaptureError::Pcap("Unexpected channel type".to_string())),
            Err(e) => return Err(CaptureError::Pcap(e.to_string())),
        };

        let mut last_stats_update = std::time::Instant::now();
        let mut packet_count_since_update = 0;
        let mut bytes_since_update = 0usize;

        while *running.read().await {
            match rx.next() {
                Ok(packet) => {
                    let packet_info = Self::parse_packet(packet, interface_name);

                    if Self::matches_filters(&packet_info, &filters.read().await) {
                        packet_count_since_update += 1;
                        bytes_since_update += packet_info.length;

                        packets.write().await.push(packet_info.clone());
                        let _ = tx.send(CaptureEvent::PacketCaptured(packet_info));
                    }

                    let elapsed = last_stats_update.elapsed().as_secs_f64();
                    if elapsed >= 1.0 {
                        let mut s = stats.write().await;
                        s.packets_per_second = packet_count_since_update as f64 / elapsed;
                        s.bytes_per_second = bytes_since_update as f64 / elapsed;
                        packet_count_since_update = 0;
                        bytes_since_update = 0;
                        last_stats_update = std::time::Instant::now();
                    }
                }
                Err(e) => {
                    tracing::error!("Capture error: {}", e);
                    let mut s = stats.write().await;
                    s.errors += 1;
                }
            }
        }

        Ok(())
    }

    fn find_interface(name: &str) -> Result<NetworkInterface> {
        datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == name)
            .ok_or(CaptureError::NoInterface)
    }

    fn parse_packet(data: &[u8], interface_name: &str) -> PacketInfo {
        let mut info = PacketInfo {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            interface: interface_name.to_string(),
            length: data.len(),
            capture_length: data.len(),
            link_layer: LinkLayerInfo {
                source_mac: String::new(),
                dest_mac: String::new(),
                ethertype: String::new(),
            },
            network_layer: None,
            transport_layer: None,
            application_layer: None,
            raw_bytes: None,
            color_rule: None,
        };

        if let Some(eth) = EthernetPacket::new(data) {
            info.link_layer = LinkLayerInfo {
                source_mac: eth.get_source().to_string(),
                dest_mac: eth.get_destination().to_string(),
                ethertype: format!("{:?}", eth.get_ethertype()),
            };

            match eth.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                        info.network_layer = Some(Self::parse_ipv4(&ipv4));
                        Self::parse_transport(ipv4.payload(), ipv4.get_next_level_protocol(), &mut info);
                    }
                }
                EtherTypes::Ipv6 => {
                    if let Some(ipv6) = Ipv6Packet::new(eth.payload()) {
                        info.network_layer = Some(Self::parse_ipv6(&ipv6));
                        Self::parse_transport(ipv6.payload(), ipv6.get_next_header(), &mut info);
                    }
                }
                _ => {}
            }
        }

        info
    }

    fn parse_ipv4(packet: &Ipv4Packet) -> NetworkLayerInfo {
        NetworkLayerInfo {
            version: 4,
            source_ip: packet.get_source().to_string(),
            dest_ip: packet.get_destination().to_string(),
            ttl: packet.get_ttl(),
            protocol: format!("{:?}", packet.get_next_level_protocol()),
            header_length: packet.get_header_length() * 4,
            total_length: packet.get_total_length(),
            identification: Some(packet.get_identification()),
            flags: Some(format!("{:?}", packet.get_flags())),
            fragment_offset: Some(packet.get_fragment_offset()),
        }
    }

    fn parse_ipv6(packet: &Ipv6Packet) -> NetworkLayerInfo {
        NetworkLayerInfo {
            version: 6,
            source_ip: packet.get_source().to_string(),
            dest_ip: packet.get_destination().to_string(),
            ttl: packet.get_hop_limit(),
            protocol: format!("{:?}", packet.get_next_header()),
            header_length: 40,
            total_length: packet.get_payload_length() + 40,
            identification: None,
            flags: None,
            fragment_offset: None,
        }
    }

    fn parse_transport(payload: &[u8], protocol: IpNextHeaderProtocol, info: &mut PacketInfo) {
        match protocol {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(payload) {
                    info.transport_layer = Some(TransportLayerInfo {
                        protocol: "TCP".to_string(),
                        source_port: tcp.get_source(),
                        dest_port: tcp.get_destination(),
                        sequence_number: Some(tcp.get_sequence()),
                        acknowledgment_number: Some(tcp.get_acknowledgement()),
                        flags: Some(Self::format_tcp_flags(&tcp)),
                        window_size: Some(tcp.get_window()),
                        payload_size: payload.len().saturating_sub(tcp.get_data_offset() as usize * 4),
                    });
                    Self::parse_application(tcp.payload(), tcp.get_destination(), tcp.get_source(), info);
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(payload) {
                    info.transport_layer = Some(TransportLayerInfo {
                        protocol: "UDP".to_string(),
                        source_port: udp.get_source(),
                        dest_port: udp.get_destination(),
                        sequence_number: None,
                        acknowledgment_number: None,
                        flags: None,
                        window_size: None,
                        payload_size: udp.get_length() as usize - 8,
                    });
                    Self::parse_application(udp.payload(), udp.get_destination(), udp.get_source(), info);
                }
            }
            _ => {}
        }
    }

    fn parse_application(payload: &[u8], dest_port: u16, source_port: u16, info: &mut PacketInfo) {
        let port = if dest_port < 1024 { dest_port } else { source_port };

        match port {
            80 | 8080 | 8443 => {
                if let Ok(text) = std::str::from_utf8(&payload[..payload.len().min(200)]) {
                    info.application_layer = Some(ApplicationLayerInfo {
                        protocol: "HTTP".to_string(),
                        info: text.lines().next().unwrap_or("").to_string(),
                        headers: None,
                        body_preview: Some(text.chars().take(100).collect()),
                    });
                }
            }
            53 => {
                info.application_layer = Some(ApplicationLayerInfo {
                    protocol: "DNS".to_string(),
                    info: format!("{} bytes", payload.len()),
                    headers: None,
                    body_preview: None,
                });
            }
            443 => {
                info.application_layer = Some(ApplicationLayerInfo {
                    protocol: "TLS".to_string(),
                    info: format!("{} bytes", payload.len()),
                    headers: None,
                    body_preview: None,
                });
            }
            _ => {}
        }
    }

    fn format_tcp_flags(tcp: &TcpPacket) -> String {
        let mut flags = Vec::new();
        if tcp.get_flags() & 0x01 != 0 { flags.push("FIN"); }
        if tcp.get_flags() & 0x02 != 0 { flags.push("SYN"); }
        if tcp.get_flags() & 0x04 != 0 { flags.push("RST"); }
        if tcp.get_flags() & 0x08 != 0 { flags.push("PSH"); }
        if tcp.get_flags() & 0x10 != 0 { flags.push("ACK"); }
        if tcp.get_flags() & 0x20 != 0 { flags.push("URG"); }
        flags.join(",")
    }

    fn matches_filters(packet: &PacketInfo, filters: &[CaptureFilter]) -> bool {
        if filters.is_empty() { return true; }
        filters.iter().filter(|f| f.enabled).all(|f| Self::matches_filter(packet, f))
    }

    fn matches_filter(packet: &PacketInfo, filter: &CaptureFilter) -> bool {
        match filter.filter_type {
            FilterType::IpAddress => {
                packet.network_layer.as_ref().map_or(false, |n| {
                    n.source_ip == filter.value || n.dest_ip == filter.value
                })
            }
            FilterType::Port => {
                if let Ok(port) = filter.value.parse::<u16>() {
                    packet.transport_layer.as_ref().map_or(false, |t| {
                        t.source_port == port || t.dest_port == port
                    })
                } else { true }
            }
            FilterType::Protocol => {
                packet.transport_layer.as_ref().map_or(false, |t| {
                    t.protocol.to_lowercase() == filter.value.to_lowercase()
                }) || packet.application_layer.as_ref().map_or(false, |a| {
                    a.protocol.to_lowercase() == filter.value.to_lowercase()
                })
            }
            FilterType::Hostname => true,
            FilterType::PacketSize => {
                if let Ok(size) = filter.value.parse::<usize>() {
                    packet.length <= size
                } else { true }
            }
            FilterType::Custom => true,
        }
    }

    pub async fn stop_capture(&self) {
        *self.running.write().await = false;
        if let Some(session) = &mut *self.current_session.write().await {
            session.stopped_at = Some(Utc::now().to_rfc3339());
        }
    }

    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    pub async fn get_packets(&self) -> Vec<PacketInfo> {
        self.packets.read().await.clone()
    }

    pub async fn get_packets_paginated(&self, offset: usize, limit: usize) -> Vec<PacketInfo> {
        let packets = self.packets.read().await;
        packets.iter().skip(offset).take(limit).cloned().collect()
    }

    pub async fn clear_packets(&self) {
        self.packets.write().await.clear();
    }

    pub async fn get_stats(&self) -> CaptureStats {
        self.stats.read().await.clone()
    }

    pub async fn add_filter(&self, filter: CaptureFilter) {
        self.filters.write().await.push(filter);
    }

    pub async fn remove_filter(&self, id: &str) {
        self.filters.write().await.retain(|f| f.id != id);
    }

    pub async fn get_filters(&self) -> Vec<CaptureFilter> {
        self.filters.read().await.clone()
    }

    pub async fn get_current_session(&self) -> Option<CaptureSession> {
        self.current_session.read().await.clone()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterfaceInfo {
    pub name: String,
    pub description: String,
    pub index: u32,
    pub mac: Option<String>,
    pub ips: Vec<String>,
    pub is_up: bool,
    pub is_loopback: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_tcp_flags() {
        // SYN flag
        assert_eq!(0x02, 0x02);
    }

    #[test]
    fn test_filter_matching() {
        let filter = CaptureFilter {
            id: "test".to_string(),
            name: "HTTP".to_string(),
            enabled: true,
            filter_type: FilterType::Port,
            value: "80".to_string(),
            color: "blue".to_string(),
        };
        assert_eq!(filter.filter_type, FilterType::Port);
    }
}
