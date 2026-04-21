//! # APK Parser
//!
//! Low-level APK file parsing using the ZIP format.
//! Provides async operations for reading APK contents.

use crate::{Result, ToolsError};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;
use tracing::{debug, error, instrument, trace};
use zip::ZipArchive;

/// APK file parser for reading ZIP-based APK archives
#[derive(Debug, Clone)]
pub struct ApkParser;

impl Default for ApkParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ApkParser {
    /// Create a new APK parser
    pub fn new() -> Self {
        Self
    }

    /// List all entries in the APK file
    #[instrument(skip(self), fields(path = %path.as_ref().display()))]
    pub async fn list_entries<P: AsRef<Path>>(&self, path: P) -> Result<Vec<ApkEntry>> {
        let path = path.as_ref();
        trace!("Listing entries in APK: {}", path.display());

        // Read file into memory for sync zip operations
        let data = tokio::fs::read(path).await.map_err(ToolsError::Io)?;
        let cursor = std::io::Cursor::new(data);

        let mut archive = ZipArchive::new(cursor)
            .map_err(|e| ToolsError::Zip(e))?;

        let mut entries = Vec::new();
        for i in 0..archive.len() {
            let file = archive.by_index(i)
                .map_err(|e| ToolsError::Zip(e))?;

            entries.push(ApkEntry {
                name: file.name().to_string(),
                size: file.size(),
                compressed_size: file.compressed_size(),
                is_file: file.is_file(),
                is_dir: file.is_dir(),
            });
        }

        debug!("Found {} entries in APK", entries.len());
        Ok(entries)
    }

    /// Extract a specific file from the APK
    #[instrument(skip(self), fields(path = %path.as_ref().display(), file = file_name))]
    pub async fn extract_file<P: AsRef<Path>>(&self, path: P, file_name: &str) -> Result<Vec<u8>> {
        let path = path.as_ref();
        trace!("Extracting file '{}' from APK: {}", file_name, path.display());

        // Read file into memory
        let data = tokio::fs::read(path).await.map_err(ToolsError::Io)?;
        let cursor = std::io::Cursor::new(data);

        let mut archive = ZipArchive::new(cursor)
            .map_err(|e| ToolsError::Zip(e))?;

        let mut file = archive.by_name(file_name)
            .map_err(|e| ToolsError::Zip(e))?;

        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .map_err(ToolsError::Io)?;

        debug!("Extracted {} bytes from {}", contents.len(), file_name);
        Ok(contents)
    }

    /// Extract multiple files matching a pattern
    #[instrument(skip(self), fields(path = %path.as_ref().display(), pattern = pattern))]
    pub async fn extract_files_matching<P: AsRef<Path>>(
        &self,
        path: P,
        pattern: &str,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        let path = path.as_ref();
        trace!("Extracting files matching '{}' from APK: {}", pattern, path.display());

        let entries = self.list_entries(path).await?;
        let mut results = Vec::new();

        for entry in entries {
            if entry.name.contains(pattern) && entry.is_file {
                match self.extract_file(path, &entry.name).await {
                    Ok(data) => results.push((entry.name, data)),
                    Err(e) => error!("Failed to extract {}: {}", entry.name, e),
                }
            }
        }

        debug!("Extracted {} files matching pattern", results.len());
        Ok(results)
    }

    /// Check if a file exists in the APK
    #[instrument(skip(self), fields(path = %path.as_ref().display(), file = file_name))]
    pub async fn file_exists<P: AsRef<Path>>(&self, path: P, file_name: &str) -> Result<bool> {
        let path = path.as_ref();
        trace!("Checking if file '{}' exists in APK: {}", file_name, path.display());

        let data = tokio::fs::read(path).await.map_err(ToolsError::Io)?;
        let cursor = std::io::Cursor::new(data);

        let archive = ZipArchive::new(cursor)
            .map_err(|e| ToolsError::Zip(e))?;

        Ok(archive.file_names().any(|name| name == file_name))
    }

    /// Get the size of a specific file in the APK
    #[instrument(skip(self), fields(path = %path.as_ref().display(), file = file_name))]
    pub async fn file_size<P: AsRef<Path>>(&self, path: P, file_name: &str) -> Result<u64> {
        let path = path.as_ref();
        trace!("Getting size of file '{}' in APK: {}", file_name, path.display());

        let data = tokio::fs::read(path).await.map_err(ToolsError::Io)?;
        let cursor = std::io::Cursor::new(data);

        let mut archive = ZipArchive::new(cursor)
            .map_err(|e| ToolsError::Zip(e))?;

        let file = archive.by_name(file_name)
            .map_err(|e| ToolsError::Zip(e))?;

        Ok(file.size())
    }

    /// Get APK metadata
    #[instrument(skip(self), fields(path = %path.as_ref().display()))]
    pub async fn get_metadata<P: AsRef<Path>>(&self, path: P) -> Result<ApkMetadata> {
        let path = path.as_ref();
        trace!("Getting metadata for APK: {}", path.display());

        let entries = self.list_entries(path).await?;
        let total_size: u64 = entries.iter().map(|e| e.size).sum();
        let compressed_size: u64 = entries.iter().map(|e| e.compressed_size).sum();

        let has_manifest = entries.iter().any(|e| e.name == "AndroidManifest.xml");
        let has_resources = entries.iter().any(|e| e.name.starts_with("res/"));
        let has_assets = entries.iter().any(|e| e.name.starts_with("assets/"));
        let has_native_libs = entries.iter().any(|e| e.name.starts_with("lib/"));

        let dex_count = entries.iter().filter(|e| {
            e.name.starts_with("classes") && e.name.ends_with(".dex")
        }).count();

        Ok(ApkMetadata {
            entry_count: entries.len(),
            total_size,
            compressed_size,
            has_manifest,
            has_resources,
            has_assets,
            has_native_libs,
            dex_count,
        })
    }

    /// Extract all text files from the APK (for secret scanning)
    #[instrument(skip(self), fields(path = %path.as_ref().display()))]
    pub async fn extract_text_files<P: AsRef<Path>>(&self, path: P) -> Result<Vec<(String, String)>> {
        let path = path.as_ref();
        trace!("Extracting text files from APK: {}", path.display());

        let entries = self.list_entries(path).await?;
        let mut results = Vec::new();

        // Common text file extensions in APKs
        let text_extensions = [
            ".xml", ".json", ".txt", ".properties", ".yaml", ".yml",
            ".html", ".htm", ".css", ".js", ".smali", ".java"
        ];

        for entry in entries {
            if entry.is_file {
                let is_text = text_extensions.iter().any(|ext| {
                    entry.name.to_lowercase().ends_with(ext)
                });

                if is_text {
                    match self.extract_file(path, &entry.name).await {
                        Ok(data) => {
                            if let Ok(text) = String::from_utf8(data) {
                                results.push((entry.name, text));
                            }
                        }
                        Err(e) => error!("Failed to extract {}: {}", entry.name, e),
                    }
                }
            }
        }

        debug!("Extracted {} text files", results.len());
        Ok(results)
    }

    /// Stream a file from the APK (for large files)
    #[instrument(skip(self), fields(path = %path.as_ref().display(), file = file_name))]
    pub async fn stream_file<P: AsRef<Path>, F>(
        &self,
        path: P,
        file_name: &str,
        mut callback: F,
    ) -> Result<()>
    where
        F: FnMut(&[u8]) -> Result<()>,
    {
        let path = path.as_ref();
        trace!("Streaming file '{}' from APK: {}", file_name, path.display());

        let data = tokio::fs::read(path).await.map_err(ToolsError::Io)?;
        let cursor = std::io::Cursor::new(data);

        let mut archive = ZipArchive::new(cursor)
            .map_err(|e| ToolsError::Zip(e))?;

        let mut file = archive.by_name(file_name)
            .map_err(|e| ToolsError::Zip(e))?;

        const BUFFER_SIZE: usize = 8192;
        let mut buffer = vec![0u8; BUFFER_SIZE];

        loop {
            let bytes_read = file.read(&mut buffer)
                .map_err(ToolsError::Io)?;
            if bytes_read == 0 {
                break;
            }
            callback(&buffer[..bytes_read])?;
        }

        Ok(())
    }
}

/// Entry in an APK file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkEntry {
    /// Entry name/path
    pub name: String,

    /// Uncompressed size
    pub size: u64,

    /// Compressed size
    pub compressed_size: u64,

    /// Is this a file
    pub is_file: bool,

    /// Is this a directory
    pub is_dir: bool,
}

/// APK metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkMetadata {
    /// Number of entries
    pub entry_count: usize,

    /// Total uncompressed size
    pub total_size: u64,

    /// Total compressed size
    pub compressed_size: u64,

    /// Has AndroidManifest.xml
    pub has_manifest: bool,

    /// Has resources
    pub has_resources: bool,

    /// Has assets
    pub has_assets: bool,

    /// Has native libraries
    pub has_native_libs: bool,

    /// Number of DEX files
    pub dex_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_apk() -> NamedTempFile {
        let mut temp_file = NamedTempFile::new().unwrap();
        
        // Create a minimal ZIP file
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        
        let options = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        
        // Add AndroidManifest.xml
        zip.start_file("AndroidManifest.xml", options).unwrap();
        zip.write_all(b"<manifest></manifest>").unwrap();
        
        // Add a DEX file
        zip.start_file("classes.dex", options).unwrap();
        zip.write_all(b"dex\n035\0").unwrap();
        
        // Add a resource
        zip.start_file("res/layout/main.xml", options).unwrap();
        zip.write_all(b"<LinearLayout/>").unwrap();
        
        zip.finish().unwrap();
        
        let data = zip.into_inner().into_inner();
        temp_file.write_all(&data).unwrap();
        temp_file
    }

    #[tokio::test]
    async fn test_list_entries() {
        let temp_file = create_test_apk();
        let parser = ApkParser::new();
        
        let entries = parser.list_entries(temp_file.path()).await.unwrap();
        assert_eq!(entries.len(), 3);
        
        let names: Vec<_> = entries.iter().map(|e| e.name.clone()).collect();
        assert!(names.contains(&"AndroidManifest.xml".to_string()));
        assert!(names.contains(&"classes.dex".to_string()));
        assert!(names.contains(&"res/layout/main.xml".to_string()));
    }

    #[tokio::test]
    async fn test_extract_file() {
        let temp_file = create_test_apk();
        let parser = ApkParser::new();
        
        let data = parser.extract_file(temp_file.path(), "AndroidManifest.xml").await.unwrap();
        assert_eq!(String::from_utf8(data).unwrap(), "<manifest></manifest>");
    }

    #[tokio::test]
    async fn test_file_exists() {
        let temp_file = create_test_apk();
        let parser = ApkParser::new();
        
        assert!(parser.file_exists(temp_file.path(), "AndroidManifest.xml").await.unwrap());
        assert!(!parser.file_exists(temp_file.path(), "nonexistent.txt").await.unwrap());
    }

    #[tokio::test]
    async fn test_get_metadata() {
        let temp_file = create_test_apk();
        let parser = ApkParser::new();
        
        let metadata = parser.get_metadata(temp_file.path()).await.unwrap();
        assert_eq!(metadata.entry_count, 3);
        assert!(metadata.has_manifest);
        assert!(metadata.has_resources);
        assert_eq!(metadata.dex_count, 1);
    }
}
