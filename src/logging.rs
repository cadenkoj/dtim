use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;
use chrono::Utc;
use log::{error, Level, LevelFilter, Metadata, Record};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::PathBuf;

use crate::crypto::SymmetricKeyManager;

#[derive(Clone, Debug)]
pub struct EncryptedLogger {
    log_path: PathBuf,
    key_mgr: SymmetricKeyManager,
    level: LevelFilter,
}

impl EncryptedLogger {
    pub fn new(
        log_path: PathBuf,
        key_mgr: SymmetricKeyManager,
        level: LevelFilter,
    ) -> std::io::Result<Self> {
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(EncryptedLogger {
            log_path,
            key_mgr,
            level,
        })
    }

    pub fn write_log(&mut self, level: Level, message: &str) -> std::io::Result<()> {
        let timestamp = Utc::now().to_rfc3339();
        let log_entry = format!("[{}] [{}] {}\n", timestamp, level, message);

        let (ciphertext, nonce, mac) = self
            .key_mgr
            .encrypt(log_entry.as_bytes())
            .map_err(|e| std::io::Error::other(format!("Encryption failed: {}", e)))?;
        let encrypted_entry = format!(
            "{}\n{}\n{}\n",
            BASE64_STANDARD.encode(ciphertext),
            BASE64_STANDARD.encode(nonce),
            BASE64_STANDARD.encode(mac)
        );

        let filename = format!("{}.log", Utc::now().format("%Y-%m-%d"));
        let log_file = self.log_path.join(filename);

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)?;

        file.write_all(encrypted_entry.as_bytes())?;
        file.flush()?;

        Ok(())
    }

    pub fn read_logs(&self, date: &str) -> std::io::Result<Vec<String>> {
        let filename = format!("{}.log", date);
        let log_file = self.log_path.join(filename);

        if !log_file.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(log_file)?;
        let mut decrypted_logs = Vec::new();

        let mut lines = content.lines().peekable();
        while lines.peek().is_some() {
            let ciphertext = lines
                .next()
                .and_then(|line| BASE64_STANDARD.decode(line).ok())
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid log format")
                })?;
            let nonce = lines
                .next()
                .and_then(|line| BASE64_STANDARD.decode(line).ok())
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid log format")
                })?;
            let mac = lines
                .next()
                .and_then(|line| BASE64_STANDARD.decode(line).ok())
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid log format")
                })?;

            match self.key_mgr.decrypt(ciphertext, nonce, mac) {
                Ok(decrypted) => {
                    if let Ok(log_entry) = String::from_utf8(decrypted) {
                        decrypted_logs.push(log_entry);
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(decrypted_logs)
    }
}

impl log::Log for EncryptedLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let mut logger = self.clone();
            if let Err(e) = logger.write_log(record.level(), &format!("{}", record.args())) {
                error!("Failed to write log: {}", e);
            }
        }
    }

    fn flush(&self) {}
}
