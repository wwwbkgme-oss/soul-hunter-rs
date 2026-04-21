//! # Signature Module
//!
//! Provides Ed25519 digital signature functionality for the evidence chain.
//!
//! ## Features
//!
//! - **Ed25519 Signatures**: Modern, fast, and secure digital signatures
//! - **Key Generation**: Generate new signing key pairs
//! - **Signature Verification**: Verify signatures against public keys
//! - **Hex Encoding**: Signatures and keys are hex-encoded for storage
//!
//! ## Security
//!
//! Ed25519 provides:
//! - Fast signature generation and verification
//! - Small signature size (64 bytes)
//! - Strong security with 128-bit security level
//! - Protection against side-channel attacks
//!
//! ## Example
//!
//! ```rust
//! use sh_evidence::signature::{SignatureManager, KeyPair};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate a new key pair
//! let keypair = KeyPair::generate()?;
//!
//! // Sign some data
//! let data = b"Hello, World!";
//! let signature = keypair.sign(data)?;
//!
//! // Verify the signature
//! let is_valid = keypair.verify(data, &signature)?;
//! assert!(is_valid);
//! # Ok(())
//! # }
//! ```

use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use rand::rngs::OsRng;

/// A key pair for signing and verification
#[derive(Debug, Clone)]
pub struct KeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl KeyPair {
    /// Generate a new random key pair
    pub fn generate() -> crate::Result<Self> {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Create a key pair from a signing key bytes
    pub fn from_signing_key_bytes(bytes: &[u8]) -> crate::Result<Self> {
        let signing_key = SigningKey::from_bytes(
            bytes.try_into()
                .map_err(|_| crate::EvidenceError::InvalidSignature("Invalid signing key length".to_string()))?
        );
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Create a key pair from a verifying key (for verification only)
    pub fn from_verifying_key_bytes(bytes: &[u8]) -> crate::Result<Self> {
        let verifying_key = VerifyingKey::from_bytes(
            bytes.try_into()
                .map_err(|_| crate::EvidenceError::InvalidSignature("Invalid verifying key length".to_string()))?
        ).map_err(|e| crate::EvidenceError::InvalidSignature(e.to_string()))?;

        // Create a dummy signing key (won't be used for signing)
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Sign data and return hex-encoded signature
    pub fn sign(&self, data: &[u8]) -> crate::Result<String> {
        let signature = self.signing_key.sign(data);
        Ok(hex::encode(signature.to_bytes()))
    }

    /// Verify a hex-encoded signature
    pub fn verify(&self, data: &[u8], signature_hex: &str) -> crate::Result<bool> {
        let signature_bytes = hex::decode(signature_hex)
            .map_err(|e| crate::EvidenceError::InvalidSignature(e.to_string()))?;

        let signature = Signature::from_bytes(
            signature_bytes.as_slice().try_into()
                .map_err(|_| crate::EvidenceError::InvalidSignature("Invalid signature length".to_string()))?
        );

        match self.verifying_key.verify(data, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Get the verifying key bytes
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Get the signing key bytes (keep this secret!)
    pub fn signing_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Get the verifying key as hex string
    pub fn verifying_key_hex(&self) -> String {
        hex::encode(self.verifying_key_bytes())
    }

    /// Get the signing key as hex string (keep this secret!)
    pub fn signing_key_hex(&self) -> String {
        hex::encode(self.signing_key_bytes())
    }
}

/// Signature manager for handling multiple signatures
#[derive(Debug, Default)]
pub struct SignatureManager {
    keypairs: Vec<KeyPair>,
}

impl SignatureManager {
    /// Create a new signature manager
    pub fn new() -> Self {
        Self {
            keypairs: Vec::new(),
        }
    }

    /// Add a key pair to the manager
    pub fn add_keypair(&mut self, keypair: KeyPair) {
        self.keypairs.push(keypair);
    }

    /// Generate and add a new key pair
    pub fn generate_keypair(&mut self) -> crate::Result<&KeyPair> {
        let keypair = KeyPair::generate()?;
        self.keypairs.push(keypair);
        Ok(self.keypairs.last().unwrap())
    }

    /// Sign data with the first available key pair
    pub fn sign(&self, data: &[u8]) -> crate::Result<Option<String>> {
        if let Some(keypair) = self.keypairs.first() {
            Ok(Some(keypair.sign(data)?))
        } else {
            Ok(None)
        }
    }

    /// Verify a signature with any of the stored key pairs
    pub fn verify(&self, data: &[u8], signature_hex: &str) -> crate::Result<bool> {
        for keypair in &self.keypairs {
            if keypair.verify(data, signature_hex)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Verify a signature with a specific verifying key
    pub fn verify_with_key(
        data: &[u8],
        signature_hex: &str,
        verifying_key_hex: &str,
    ) -> crate::Result<bool> {
        let verifying_key_bytes = hex::decode(verifying_key_hex)
            .map_err(|e| crate::EvidenceError::InvalidSignature(e.to_string()))?;

        let keypair = KeyPair::from_verifying_key_bytes(&verifying_key_bytes)?;
        keypair.verify(data, signature_hex)
    }

    /// Get the number of key pairs
    pub fn keypair_count(&self) -> usize {
        self.keypairs.len()
    }

    /// Check if any key pairs are available
    pub fn has_keypair(&self) -> bool {
        !self.keypairs.is_empty()
    }
}

/// Standalone function to verify a signature
pub fn verify_signature(
    data: &[u8],
    signature_hex: &str,
    verifying_key_hex: &str,
) -> crate::Result<bool> {
    SignatureManager::verify_with_key(data, signature_hex, verifying_key_hex)
}

/// Standalone function to sign data
pub fn sign_data(data: &[u8], signing_key_hex: &str) -> crate::Result<String> {
    let signing_key_bytes = hex::decode(signing_key_hex)
        .map_err(|e| crate::EvidenceError::InvalidSignature(e.to_string()))?;

    let keypair = KeyPair::from_signing_key_bytes(&signing_key_bytes)?;
    keypair.sign(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        assert_eq!(keypair.verifying_key_bytes().len(), 32);
        assert_eq!(keypair.signing_key_bytes().len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let data = b"Hello, World!";

        let signature = keypair.sign(data).expect("Failed to sign");
        assert_eq!(signature.len(), 128); // 64 bytes = 128 hex chars

        let is_valid = keypair.verify(data, &signature).expect("Failed to verify");
        assert!(is_valid);
    }

    #[test]
    fn test_verify_invalid_signature() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let data = b"Hello, World!";

        let signature = keypair.sign(data).expect("Failed to sign");

        // Verify with wrong data
        let is_valid = keypair.verify(b"Wrong data", &signature).expect("Failed to verify");
        assert!(!is_valid);
    }

    #[test]
    fn test_verify_wrong_signature() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let data = b"Hello, World!";

        // Create a different keypair and sign with it
        let other_keypair = KeyPair::generate().expect("Failed to generate other keypair");
        let other_signature = other_keypair.sign(data).expect("Failed to sign");

        // Verify with wrong keypair
        let is_valid = keypair.verify(data, &other_signature).expect("Failed to verify");
        assert!(!is_valid);
    }

    #[test]
    fn test_keypair_from_bytes() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let signing_key_bytes = keypair.signing_key_bytes();

        let reconstructed = KeyPair::from_signing_key_bytes(&signing_key_bytes)
            .expect("Failed to reconstruct keypair");

        assert_eq!(keypair.verifying_key_bytes(), reconstructed.verifying_key_bytes());

        // Test signing with reconstructed keypair
        let data = b"test data";
        let sig1 = keypair.sign(data).expect("Failed to sign");
        let sig2 = reconstructed.sign(data).expect("Failed to sign");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_verifying_key_only() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let verifying_key_bytes = keypair.verifying_key_bytes();

        let verifying_only = KeyPair::from_verifying_key_bytes(&verifying_key_bytes)
            .expect("Failed to create verifying-only keypair");

        // Should be able to verify
        let data = b"test data";
        let signature = keypair.sign(data).expect("Failed to sign");
        let is_valid = verifying_only.verify(data, &signature).expect("Failed to verify");
        assert!(is_valid);
    }

    #[test]
    fn test_hex_encoding() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");

        let verifying_hex = keypair.verifying_key_hex();
        assert_eq!(verifying_hex.len(), 64); // 32 bytes = 64 hex chars

        let signing_hex = keypair.signing_key_hex();
        assert_eq!(signing_hex.len(), 64);
    }

    #[test]
    fn test_signature_manager() {
        let mut manager = SignatureManager::new();
        assert!(!manager.has_keypair());
        assert_eq!(manager.keypair_count(), 0);

        manager.generate_keypair().expect("Failed to generate keypair");
        assert!(manager.has_keypair());
        assert_eq!(manager.keypair_count(), 1);

        let data = b"test data";
        let signature = manager.sign(data).expect("Failed to sign").expect("No signature");

        let is_valid = manager.verify(data, &signature).expect("Failed to verify");
        assert!(is_valid);
    }

    #[test]
    fn test_signature_manager_multiple_keypairs() {
        let mut manager = SignatureManager::new();

        let keypair1 = KeyPair::generate().expect("Failed to generate keypair");
        let keypair2 = KeyPair::generate().expect("Failed to generate keypair");

        manager.add_keypair(keypair1);
        manager.add_keypair(keypair2);

        assert_eq!(manager.keypair_count(), 2);
    }

    #[test]
    fn test_standalone_verify() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let data = b"test data";

        let signature = keypair.sign(data).expect("Failed to sign");
        let verifying_key_hex = keypair.verifying_key_hex();

        let is_valid = verify_signature(data, &signature, &verifying_key_hex)
            .expect("Failed to verify");
        assert!(is_valid);
    }

    #[test]
    fn test_standalone_sign() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let data = b"test data";
        let signing_key_hex = keypair.signing_key_hex();

        let signature = sign_data(data, &signing_key_hex).expect("Failed to sign");

        let is_valid = keypair.verify(data, &signature).expect("Failed to verify");
        assert!(is_valid);
    }

    #[test]
    fn test_invalid_signature_hex() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let data = b"test data";

        let result = keypair.verify(data, "invalid hex");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_signature_length() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let data = b"test data";

        // Valid hex but wrong length
        let result = keypair.verify(data, "abcd");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_bytes() {
        let result = KeyPair::from_signing_key_bytes(&[1, 2, 3]);
        assert!(result.is_err());

        let result = KeyPair::from_verifying_key_bytes(&[1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_signature_determinism() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let data = b"test data";

        // Ed25519 signatures are deterministic
        let sig1 = keypair.sign(data).expect("Failed to sign");
        let sig2 = keypair.sign(data).expect("Failed to sign");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_empty_data() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let data = b"";

        let signature = keypair.sign(data).expect("Failed to sign");
        let is_valid = keypair.verify(data, &signature).expect("Failed to verify");
        assert!(is_valid);
    }

    #[test]
    fn test_large_data() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let data = vec![0u8; 1024 * 1024]; // 1MB of data

        let signature = keypair.sign(&data).expect("Failed to sign");
        let is_valid = keypair.verify(&data, &signature).expect("Failed to verify");
        assert!(is_valid);
    }
}
