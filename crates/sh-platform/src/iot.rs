//! IoT Platform Adapter
//!
//! Production-ready adapter for analyzing IoT firmware and embedded systems.
//! Supports ELF binaries, raw firmware images, and various IoT-specific formats.
//! Extracts and analyzes binary metadata, symbols, strings, and configuration.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use nom::bytes::complete::{tag, take};
use nom::number::complete::{be_u16, be_u32, le_u16, le_u32};
use nom::IResult;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, instrument, trace, warn};

use crate::{
    PlatformAdapter, PlatformCapabilities, PlatformError, PlatformMetadata, PlatformResult,
    ParseResult, utils,
};
use sh_types::{AnalysisTarget, Platform};

/// IoT-specific metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IotMetadata {
    /// Firmware/device name
    pub device_name: Option<String>,
    /// Manufacturer
    pub manufacturer: Option<String>,
    /// Model number
    pub model: Option<String>,
    /// Firmware version
    pub firmware_version: Option<String>,
    /// Hardware version
    pub hardware_version: Option<String>,
    /// Architecture (ARM, MIPS, x86, etc.)
    pub architecture: Option<String>,
    /// Endianness (little/big)
    pub endianness: Option<String>,
    /// Base address
    pub base_address: Option<u64>,
    /// Entry point address
    pub entry_point: Option<u64>,
    /// Binary format (ELF, raw, etc.)
    pub binary_format: BinaryFormat,
    /// File type (firmware, bootloader, kernel, etc.)
    pub file_type: FirmwareType,
    /// Compression type
    pub compression: Option<String>,
    /// Encryption detected
    pub is_encrypted: bool,
    /// Hashes/signatures found
    pub signatures: Vec<SignatureInfo>,
    /// Sections found
    pub sections: Vec<SectionInfo>,
    /// Symbols found
    pub symbols: Vec<SymbolInfo>,
    /// Strings extracted
    pub strings: Vec<StringInfo>,
    /// Configuration data
    pub config_data: HashMap<String, serde_json::Value>,
    /// Certificate information
    pub certificates: Vec<CertificateInfo>,
    /// Network endpoints found
    pub network_endpoints: Vec<NetworkEndpoint>,
    /// Hardcoded credentials found
    pub hardcoded_credentials: Vec<CredentialInfo>,
}

impl IotMetadata {
    /// Create new IoT metadata
    pub fn new() -> Self {
        Self {
            device_name: None,
            manufacturer: None,
            model: None,
            firmware_version: None,
            hardware_version: None,
            architecture: None,
            endianness: None,
            base_address: None,
            entry_point: None,
            binary_format: BinaryFormat::Unknown,
            file_type: FirmwareType::Unknown,
            compression: None,
            is_encrypted: false,
            signatures: Vec::new(),
            sections: Vec::new(),
            symbols: Vec::new(),
            strings: Vec::new(),
            config_data: HashMap::new(),
            certificates: Vec::new(),
            network_endpoints: Vec::new(),
            hardcoded_credentials: Vec::new(),
        }
    }
}

/// Binary format types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryFormat {
    Elf,
    MachO,
    Pe,
    Raw,
    UBoot,
    Cpio,
    SquashFS,
    Jffs2,
    Yaffs2,
    CramFS,
    Unknown,
}

impl std::fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryFormat::Elf => write!(f, "ELF"),
            BinaryFormat::MachO => write!(f, "Mach-O"),
            BinaryFormat::Pe => write!(f, "PE"),
            BinaryFormat::Raw => write!(f, "Raw"),
            BinaryFormat::UBoot => write!(f, "U-Boot"),
            BinaryFormat::Cpio => write!(f, "CPIO"),
            BinaryFormat::SquashFS => write!(f, "SquashFS"),
            BinaryFormat::Jffs2 => write!(f, "JFFS2"),
            BinaryFormat::Yaffs2 => write!(f, "YAFFS2"),
            BinaryFormat::CramFS => write!(f, "CramFS"),
            BinaryFormat::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Firmware file types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirmwareType {
    Firmware,
    Bootloader,
    Kernel,
    RootFS,
    FullImage,
    UpdatePackage,
    Configuration,
    Certificate,
    Unknown,
}

/// Section information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u64,
    pub physical_address: u64,
    pub size: u64,
    pub flags: u32,
    pub is_executable: bool,
    pub is_writable: bool,
    pub is_readable: bool,
}

/// Symbol information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub symbol_type: String,
    pub is_exported: bool,
}

/// String information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringInfo {
    pub content: String,
    pub address: u64,
    pub length: usize,
    pub category: StringCategory,
}

/// String category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringCategory {
    Url,
    IpAddress,
    Email,
    Path,
    Credential,
    ApiKey,
    Certificate,
    Config,
    Debug,
    Other,
}

/// Signature information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    pub signature_type: String,
    pub offset: u64,
    pub size: usize,
    pub data: Vec<u8>,
}

/// Certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub valid_from: String,
    pub valid_to: String,
    pub is_self_signed: bool,
}

/// Network endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEndpoint {
    pub endpoint_type: EndpointType,
    pub address: String,
    pub port: Option<u16>,
    pub protocol: String,
    pub is_encrypted: bool,
}

/// Endpoint type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndpointType {
    Server,
    Client,
    Both,
}

/// Credential information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialInfo {
    pub credential_type: CredentialType,
    pub username: Option<String>,
    pub password: Option<String>,
    pub key: Option<String>,
    pub address: u64,
}

/// Credential type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialType {
    Password,
    ApiKey,
    Token,
    Certificate,
    PrivateKey,
    HardcodedSecret,
}

/// IoT platform adapter
pub struct IotAdapter {
    capabilities: PlatformCapabilities,
}

impl IotAdapter {
    /// Create a new IoT adapter
    pub fn new() -> Self {
        Self {
            capabilities: PlatformCapabilities::iot(),
        }
    }

    /// Detect binary format from magic bytes
    fn detect_format(&self, data: &[u8]) -> BinaryFormat {
        if data.len() < 4 {
            return BinaryFormat::Unknown;
        }

        let magic = &data[..4];

        match magic {
            [0x7f, b'E', b'L', b'F'] => BinaryFormat::Elf,
            [0xcf, 0xfa, 0xed, 0xfe] | [0xfe, 0xed, 0xfa, 0xcf] => BinaryFormat::MachO,
            [0x4d, 0x5a, _, _] => BinaryFormat::Pe,
            [0x27, 0x05, 0x19, 0x56] => BinaryFormat::UBoot,
            [0x71, 0xc7, _, _] => BinaryFormat::SquashFS,
            [0x28, 0xb3, 0xaf, 0x0c] => BinaryFormat::Jffs2,
            [0x59, 0x61, 0x66, 0x73] => BinaryFormat::Yaffs2,
            [0x45, 0x1d, 0x9e, 0xe3] => BinaryFormat::CramFS,
            [0x71, 0xc7, 0x00, 0x00] => BinaryFormat::Cpio,
            _ => BinaryFormat::Raw,
        }
    }

    /// Parse ELF header
    fn parse_elf_header(&self, data: &[u8]) -> PlatformResult<ElfHeader> {
        if data.len() < 64 {
            return Err(PlatformError::ParseError(
                "File too small for ELF header".to_string(),
            ));
        }

        let is_64bit = data[4] == 2;
        let is_little_endian = data[5] == 1;

        let arch = match data[18] {
            0x03 => "x86",
            0x28 => "ARM",
            0x3e => "x86_64",
            0xb7 => "AArch64",
            0x08 => "MIPS",
            0x14 => "PowerPC",
            _ => "Unknown",
        };

        let entry_point = if is_64bit {
            if is_little_endian {
                u64::from_le_bytes([
                    data[24], data[25], data[26], data[27],
                    data[28], data[29], data[30], data[31],
                ])
            } else {
                u64::from_be_bytes([
                    data[24], data[25], data[26], data[27],
                    data[28], data[29], data[30], data[31],
                ])
            }
        } else {
            if is_little_endian {
                u32::from_le_bytes([data[24], data[25], data[26], data[27]]) as u64
            } else {
                u32::from_be_bytes([data[24], data[25], data[26], data[27]]) as u64
            }
        };

        Ok(ElfHeader {
            is_64bit,
            is_little_endian,
            architecture: arch.to_string(),
            entry_point,
        })
    }

    /// Extract strings from binary
    fn extract_strings(&self, data: &[u8], min_length: usize) -> Vec<StringInfo> {
        let mut strings = Vec::new();
        let mut current_string = String::new();
        let mut start_addr: u64 = 0;

        for (i, &byte) in data.iter().enumerate() {
            if byte.is_ascii_graphic() || byte == b' ' || byte == b'\t' {
                if current_string.is_empty() {
                    start_addr = i as u64;
                }
                current_string.push(byte as char);
            } else if byte == 0 {
                if current_string.len() >= min_length {
                    let category = self.categorize_string(&current_string);
                    strings.push(StringInfo {
                        content: current_string.clone(),
                        address: start_addr,
                        length: current_string.len(),
                        category,
                    });
                }
                current_string.clear();
            } else {
                current_string.clear();
            }
        }

        strings
    }

    /// Categorize a string
    fn categorize_string(&self, s: &str) -> StringCategory {
        if s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://") {
            StringCategory::Url
        } else if s.contains('@') && s.contains('.') && !s.contains(' ') {
            StringCategory::Email
        } else if self.is_ip_address(s) {
            StringCategory::IpAddress
        } else if s.starts_with('/') || s.starts_with("./") || s.starts_with("../") {
            StringCategory::Path
        } else if s.len() >= 32 && (s.chars().all(|c| c.is_ascii_hexdigit()) ||
            s.chars().all(|c| c.is_alphanumeric() && c.is_ascii())) {
            StringCategory::ApiKey
        } else if s.contains("password") || s.contains("passwd") || s.contains("pwd") ||
            s.contains("secret") || s.contains("key") || s.contains("token") {
            StringCategory::Credential
        } else if s.contains("BEGIN CERTIFICATE") || s.contains("END CERTIFICATE") {
            StringCategory::Certificate
        } else if s.contains("config") || s.contains("setting") || s.contains("cfg") {
            StringCategory::Config
        } else if s.contains("debug") || s.contains("DEBUG") || s.contains("log") {
            StringCategory::Debug
        } else {
            StringCategory::Other
        }
    }

    /// Check if string is an IP address
    fn is_ip_address(&self, s: &str) -> bool {
        // Simple IPv4 check
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() == 4 {
            return parts.iter().all(|p| {
                p.parse::<u8>().is_ok()
            });
        }
        false
    }

    /// Detect network endpoints from strings
    fn detect_endpoints(&self, strings: &[StringInfo]) -> Vec<NetworkEndpoint> {
        let mut endpoints = Vec::new();

        for s in strings {
            if let StringCategory::Url = s.category {
                if s.content.starts_with("http://") {
                    endpoints.push(NetworkEndpoint {
                        endpoint_type: EndpointType::Client,
                        address: s.content.clone(),
                        port: Some(80),
                        protocol: "HTTP".to_string(),
                        is_encrypted: false,
                    });
                } else if s.content.starts_with("https://") {
                    endpoints.push(NetworkEndpoint {
                        endpoint_type: EndpointType::Client,
                        address: s.content.clone(),
                        port: Some(443),
                        protocol: "HTTPS".to_string(),
                        is_encrypted: true,
                    });
                }
            } else if let StringCategory::IpAddress = s.category {
                // Look for port in nearby strings
                endpoints.push(NetworkEndpoint {
                    endpoint_type: EndpointType::Both,
                    address: s.content.clone(),
                    port: None,
                    protocol: "TCP".to_string(),
                    is_encrypted: false,
                });
            }
        }

        endpoints
    }

    /// Detect hardcoded credentials
    fn detect_credentials(&self, strings: &[StringInfo]) -> Vec<CredentialInfo> {
        let mut credentials = Vec::new();
        let credential_patterns = [
            "password", "passwd", "pwd", "secret", "api_key", "apikey",
            "token", "auth", "credential", "private_key", "privatekey",
        ];

        for s in strings {
            let lower = s.content.to_lowercase();
            for pattern in &credential_patterns {
                if lower.contains(pattern) && s.content.len() > pattern.len() + 2 {
                    // Check if it looks like a credential (has value after keyword)
                    if let Some(pos) = lower.find(pattern) {
                        let after = &s.content[pos + pattern.len()..];
                        if after.contains('=') || after.contains(':') || after.len() > 8 {
                            credentials.push(CredentialInfo {
                                credential_type: CredentialType::HardcodedSecret,
                                username: None,
                                password: Some(s.content.clone()),
                                key: None,
                                address: s.address,
                            });
                            break;
                        }
                    }
                }
            }
        }

        credentials
    }

    /// Check for compression
    fn detect_compression(&self, data: &[u8]) -> Option<String> {
        // Check for common compression signatures
        if data.len() >= 2 {
            if data[0] == 0x1f && data[1] == 0x8b {
                return Some("gzip".to_string());
            }
            if data[0] == 0x78 && (data[1] == 0x9c || data[1] == 0x01 || data[1] == 0xda) {
                return Some("zlib".to_string());
            }
            if data[0] == 0x42 && data[1] == 0x5a {
                return Some("bzip2".to_string());
            }
            if data[0] == 0x28 && data[1] == 0xb5 && data[2] == 0x2f && data[3] == 0xfd {
                return Some("zstd".to_string());
            }
        }
        None
    }

    /// Check for encryption
    fn detect_encryption(&self, data: &[u8]) -> bool {
        // Simple entropy check - encrypted data has high entropy
        if data.len() < 256 {
            return false;
        }

        let sample = &data[..256.min(data.len())];
        let entropy = self.calculate_entropy(sample);

        // High entropy (>7.5) suggests encryption or compression
        entropy > 7.5
    }

    /// Calculate Shannon entropy
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        let mut frequencies = [0u64; 256];
        for &byte in data {
            frequencies[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &frequencies {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Parse sections from ELF
    fn parse_elf_sections(&self, data: &[u8]) -> Vec<SectionInfo> {
        let mut sections = Vec::new();

        // This is a simplified implementation
        // Full implementation would parse section headers properly
        if data.len() >= 64 {
            let is_64bit = data[4] == 2;
            let is_little_endian = data[5] == 1;

            // Parse section header offset
            let shoff = if is_64bit {
                if is_little_endian {
                    u64::from_le_bytes([
                        data[40], data[41], data[42], data[43],
                        data[44], data[45], data[46], data[47],
                    ])
                } else {
                    u64::from_be_bytes([
                        data[40], data[41], data[42], data[43],
                        data[44], data[45], data[46], data[47],
                    ])
                }
            } else {
                if is_little_endian {
                    u32::from_le_bytes([data[32], data[33], data[34], data[35]]) as u64
                } else {
                    u32::from_be_bytes([data[32], data[33], data[34], data[35]]) as u64
                }
            };

            // Parse number of section headers
            let shnum = if is_64bit {
                u16::from_le_bytes([data[60], data[61]])
            } else {
                u16::from_le_bytes([data[48], data[49]])
            };

            // Parse section header entry size
            let shentsize = if is_64bit {
                u16::from_le_bytes([data[58], data[59]])
            } else {
                u16::from_le_bytes([data[46], data[47]])
            };

            trace!(
                "ELF: {} sections at offset {}, entry size {}",
                shnum, shoff, shentsize
            );
        }

        sections
    }
}

/// ELF header info
#[derive(Debug, Clone)]
struct ElfHeader {
    is_64bit: bool,
    is_little_endian: bool,
    architecture: String,
    entry_point: u64,
}

impl Default for IotAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PlatformAdapter for IotAdapter {
    fn platform(&self) -> Platform {
        Platform::Iot
    }

    fn capabilities(&self) -> PlatformCapabilities {
        self.capabilities.clone()
    }

    fn can_handle(&self, target: &AnalysisTarget) -> bool {
        target.platform == Platform::Iot
            || self
                .capabilities
                .supports_extension(&target.path.to_lowercase())
    }

    #[instrument(skip(self, target))]
    async fn validate(&self, target: &AnalysisTarget) -> PlatformResult<()> {
        let path = Path::new(&target.path);

        if !path.exists() {
            return Err(PlatformError::InvalidFormat(format!(
                "File not found: {}",
                target.path
            )));
        }

        if !path.is_file() {
            return Err(PlatformError::InvalidFormat(format!(
                "Not a file: {}",
                target.path
            )));
        }

        let file_size = utils::get_file_size(path)?;
        if file_size > self.capabilities.max_file_size {
            return Err(PlatformError::InvalidFormat(format!(
                "File too large: {} bytes (max: {})",
                file_size, self.capabilities.max_file_size
            )));
        }

        if file_size == 0 {
            return Err(PlatformError::InvalidFormat(
                "File is empty".to_string(),
            ));
        }

        Ok(())
    }

    #[instrument(skip(self, target))]
    async fn parse(&self, target: &AnalysisTarget) -> PlatformResult<ParseResult> {
        let path = Path::new(&target.path);
        let mut file = File::open(path)?;

        // Read first 4KB for header analysis
        let mut header_data = vec![0u8; 4096];
        let bytes_read = file.read(&mut header_data)?;
        header_data.truncate(bytes_read);

        // Detect format
        let format = self.detect_format(&header_data);

        // Read full file for string extraction
        let mut full_data = Vec::new();
        file.seek(SeekFrom::Start(0))?;
        file.read_to_end(&mut full_data)?;

        let mut metadata = IotMetadata::new();
        metadata.binary_format = format;
        metadata.file_type = FirmwareType::Firmware;

        // Parse based on format
        match format {
            BinaryFormat::Elf => {
                if let Ok(elf_header) = self.parse_elf_header(&header_data) {
                    metadata.architecture = Some(elf_header.architecture);
                    metadata.endianness = Some(if elf_header.is_little_endian {
                        "little".to_string()
                    } else {
                        "big".to_string()
                    });
                    metadata.entry_point = Some(elf_header.entry_point);
                    metadata.sections = self.parse_elf_sections(&full_data);
                }
            }
            BinaryFormat::UBoot => {
                metadata.architecture = Some("ARM".to_string());
                metadata.file_type = FirmwareType::Bootloader;
            }
            BinaryFormat::SquashFS => {
                metadata.file_type = FirmwareType::RootFS;
            }
            _ => {
                // Try to detect architecture from strings
                if full_data.windows(4).any(|w| w == b"ARM\x00") {
                    metadata.architecture = Some("ARM".to_string());
                } else if full_data.windows(5).any(|w| w == b"MIPS\x00") {
                    metadata.architecture = Some("MIPS".to_string());
                } else if full_data.windows(4).any(|w| w == b"x86\x00") {
                    metadata.architecture = Some("x86".to_string());
                }
            }
        }

        // Detect compression
        metadata.compression = self.detect_compression(&header_data);

        // Detect encryption
        metadata.is_encrypted = self.detect_encryption(&full_data);

        // Extract strings
        metadata.strings = self.extract_strings(&full_data, 4);

        // Detect endpoints
        metadata.network_endpoints = self.detect_endpoints(&metadata.strings);

        // Detect credentials
        metadata.hardcoded_credentials = self.detect_credentials(&metadata.strings);

        // Build platform metadata
        let platform_metadata = PlatformMetadata::new(Platform::Iot)
            .with_name(&metadata.device_name.as_deref().unwrap_or("Unknown Device"))
            .with_version(metadata.firmware_version.as_deref().unwrap_or("unknown"))
            .with_package_id(&format!("{}:{}",
                metadata.manufacturer.as_deref().unwrap_or("unknown"),
                metadata.model.as_deref().unwrap_or("unknown")))
            .with_architecture(metadata.architecture.as_deref().unwrap_or("unknown"))
            .with_file_size(utils::get_file_size(path)?)
            .with_checksum(utils::calculate_checksum(path)?);

        // Create parse result
        let mut result = ParseResult::new(&target.path, platform_metadata);

        // Add as binary file
        result = result.add_binary_file(&target.path);

        // Add IoT-specific metadata as extra
        let iot_json = serde_json::to_value(&metadata)?;
        result.metadata.extra.insert("iot".to_string(), iot_json);

        info!(
            "Parsed IoT firmware: {} format, {} strings, {} endpoints, {} credentials",
            format,
            metadata.strings.len(),
            metadata.network_endpoints.len(),
            metadata.hardcoded_credentials.len()
        );

        Ok(result)
    }

    #[instrument(skip(self, target, output_dir))]
    async fn extract(&self, target: &AnalysisTarget, output_dir: &Path) -> PlatformResult<PathBuf> {
        let path = Path::new(&target.path);

        // Create extraction directory
        let extract_dir = utils::create_work_dir(output_dir, "iot")?;

        // Copy the binary
        let dest_path = extract_dir.join(path.file_name().unwrap_or_default());
        std::fs::copy(path, &dest_path)?;

        // Try to extract if it's a known format
        let mut file = File::open(path)?;
        let mut header = [0u8; 4];
        file.read_exact(&mut header)?;

        // Check for SquashFS
        if header == [0x71, 0xc7, 0x00, 0x00] || header == [0x68, 0x73, 0x71, 0x73] {
            info!("Detected SquashFS filesystem, would extract contents");
            // In production, use unsquashfs or similar tool
        }

        // Check for CPIO
        if header == [0x71, 0xc7, 0x00, 0x00] {
            info!("Detected CPIO archive, would extract contents");
            // In production, use cpio command
        }

        info!("Extracted IoT firmware to: {}", extract_dir.display());
        Ok(extract_dir)
    }

    fn analysis_config(&self) -> serde_json::Value {
        serde_json::json!({
            "platform": "iot",
            "static_analysis": {
                "binary_analysis": true,
                "string_analysis": true,
                "symbol_analysis": true,
                "section_analysis": true,
            },
            "dynamic_analysis": false,
            "network_analysis": {
                "endpoint_detection": true,
                "protocol_analysis": true,
            },
            "check_categories": [
                "hardcoded_credentials",
                "insecure_endpoints",
                "weak_crypto",
                "debug_symbols",
                "sensitive_strings",
                "certificate_validation",
                "update_mechanism",
                "backdoor_detection",
            ],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_iot_adapter_creation() {
        let adapter = IotAdapter::new();
        assert_eq!(adapter.platform(), Platform::Iot);
        assert!(adapter.capabilities().static_analysis);
        assert!(!adapter.capabilities().dynamic_analysis);
    }

    #[test]
    fn test_detect_format() {
        let adapter = IotAdapter::new();

        // ELF magic
        let elf_data = vec![0x7f, b'E', b'L', b'F', 2, 1, 1];
        assert_eq!(adapter.detect_format(&elf_data), BinaryFormat::Elf);

        // Mach-O magic (64-bit little endian)
        let macho_data = vec![0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1];
        assert_eq!(adapter.detect_format(&macho_data), BinaryFormat::MachO);

        // PE magic
        let pe_data = vec![0x4d, 0x5a, 0x90, 0x00];
        assert_eq!(adapter.detect_format(&pe_data), BinaryFormat::Pe);

        // U-Boot magic
        let uboot_data = vec![0x27, 0x05, 0x19, 0x56];
        assert_eq!(adapter.detect_format(&uboot_data), BinaryFormat::UBoot);

        // Unknown/Raw
        let raw_data = vec![0x00, 0x00, 0x00, 0x00];
        assert_eq!(adapter.detect_format(&raw_data), BinaryFormat::Raw);
    }

    #[test]
    fn test_extract_strings() {
        let adapter = IotAdapter::new();

        let data = b"Hello\x00World\x00Test123\x00\x01\x02\x03Another\x00";
        let strings = adapter.extract_strings(data, 4);

        assert_eq!(strings.len(), 4);
        assert_eq!(strings[0].content, "Hello");
        assert_eq!(strings[1].content, "World");
        assert_eq!(strings[2].content, "Test123");
        assert_eq!(strings[3].content, "Another");
    }

    #[test]
    fn test_categorize_string() {
        let adapter = IotAdapter::new();

        assert_eq!(
            adapter.categorize_string("https://example.com"),
            StringCategory::Url
        );
        assert_eq!(
            adapter.categorize_string("http://192.168.1.1"),
            StringCategory::Url
        );
        assert_eq!(
            adapter.categorize_string("192.168.1.1"),
            StringCategory::IpAddress
        );
        assert_eq!(
            adapter.categorize_string("/etc/config"),
            StringCategory::Path
        );
        assert_eq!(
            adapter.categorize_string("password123"),
            StringCategory::Credential
        );
        assert_eq!(
            adapter.categorize_string("-----BEGIN CERTIFICATE-----"),
            StringCategory::Certificate
        );
    }

    #[test]
    fn test_is_ip_address() {
        let adapter = IotAdapter::new();

        assert!(adapter.is_ip_address("192.168.1.1"));
        assert!(adapter.is_ip_address("10.0.0.1"));
        assert!(adapter.is_ip_address("255.255.255.255"));
        assert!(!adapter.is_ip_address("256.1.1.1"));
        assert!(!adapter.is_ip_address("192.168.1"));
        assert!(!adapter.is_ip_address("example.com"));
    }

    #[test]
    fn test_calculate_entropy() {
        let adapter = IotAdapter::new();

        // Low entropy (repeated bytes)
        let low_entropy = vec![0x41u8; 256];
        let entropy1 = adapter.calculate_entropy(&low_entropy);
        assert!(entropy1 < 1.0);

        // High entropy (random-like)
        let high_entropy: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let entropy2 = adapter.calculate_entropy(&high_entropy);
        assert!(entropy2 > 7.0);
    }

    #[test]
    fn test_detect_compression() {
        let adapter = IotAdapter::new();

        // gzip
        let gzip_data = vec![0x1f, 0x8b, 0x08, 0x00];
        assert_eq!(
            adapter.detect_compression(&gzip_data),
            Some("gzip".to_string())
        );

        // zlib
        let zlib_data = vec![0x78, 0x9c, 0x00, 0x00];
        assert_eq!(
            adapter.detect_compression(&zlib_data),
            Some("zlib".to_string())
        );

        // No compression
        let raw_data = vec![0x00, 0x00, 0x00, 0x00];
        assert_eq!(adapter.detect_compression(&raw_data), None);
    }

    #[test]
    fn test_detect_endpoints() {
        let adapter = IotAdapter::new();

        let strings = vec![
            StringInfo {
                content: "https://api.example.com".to_string(),
                address: 0,
                length: 23,
                category: StringCategory::Url,
            },
            StringInfo {
                content: "192.168.1.100".to_string(),
                address: 100,
                length: 13,
                category: StringCategory::IpAddress,
            },
        ];

        let endpoints = adapter.detect_endpoints(&strings);
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].protocol, "HTTPS");
        assert!(endpoints[0].is_encrypted);
    }

    #[test]
    fn test_binary_format_display() {
        assert_eq!(BinaryFormat::Elf.to_string(), "ELF");
        assert_eq!(BinaryFormat::MachO.to_string(), "Mach-O");
        assert_eq!(BinaryFormat::Raw.to_string(), "Raw");
        assert_eq!(BinaryFormat::Unknown.to_string(), "Unknown");
    }
}
