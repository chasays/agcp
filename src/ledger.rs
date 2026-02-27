use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::Serialize;
use thiserror::Error;

use crate::crypto::{compute_audit_record_hash, hash_json, now_rfc3339, CryptoError};
use crate::proto::AuditRecord;

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("hash chain broken at seq={0}")]
    ChainBroken(u64),
}

#[derive(Default)]
struct LedgerInner {
    next_seq: u64,
    last_hash: String,
    by_action: HashMap<String, Vec<AuditRecord>>,
}

pub struct AuditLedger {
    path: PathBuf,
    inner: Mutex<LedgerInner>,
}

impl AuditLedger {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        if !path.exists() {
            OpenOptions::new().create(true).append(true).open(&path)?;
        }

        let mut inner = LedgerInner::default();
        for record in read_records(&path)? {
            inner.next_seq = record.seq;
            inner.last_hash = record.record_hash.clone();
            inner
                .by_action
                .entry(record.action_id.clone())
                .or_default()
                .push(record);
        }

        Ok(Self {
            path,
            inner: Mutex::new(inner),
        })
    }

    pub fn append_event<T: Serialize>(
        &self,
        action_id: &str,
        event_type: &str,
        payload: &T,
        signer: &str,
    ) -> Result<AuditRecord, LedgerError> {
        let payload_hash = hash_json(payload)?;

        let mut inner = self.inner.lock().expect("ledger lock poisoned");
        let seq = inner.next_seq + 1;
        let mut record = AuditRecord {
            seq,
            ts: now_rfc3339(),
            event_type: event_type.to_string(),
            action_id: action_id.to_string(),
            payload_hash,
            prev_hash: inner.last_hash.clone(),
            record_hash: String::new(),
            signer: signer.to_string(),
        };

        record.record_hash = compute_audit_record_hash(&record)?;

        let mut file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        let line = serde_json::to_string(&record)?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;

        inner.next_seq = seq;
        inner.last_hash = record.record_hash.clone();
        inner
            .by_action
            .entry(action_id.to_string())
            .or_default()
            .push(record.clone());

        Ok(record)
    }

    pub fn records_for_action(&self, action_id: &str) -> Vec<AuditRecord> {
        self.inner
            .lock()
            .expect("ledger lock poisoned")
            .by_action
            .get(action_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn verify_chain(&self) -> Result<(), LedgerError> {
        let mut last_hash = String::new();
        for record in read_records(&self.path)? {
            if record.prev_hash != last_hash {
                return Err(LedgerError::ChainBroken(record.seq));
            }
            let expected = compute_audit_record_hash(&record)?;
            if expected != record.record_hash {
                return Err(LedgerError::ChainBroken(record.seq));
            }
            last_hash = record.record_hash;
        }
        Ok(())
    }
}

fn read_records(path: &Path) -> Result<Vec<AuditRecord>, LedgerError> {
    let file = OpenOptions::new().read(true).open(path)?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        records.push(serde_json::from_str::<AuditRecord>(&line)?);
    }

    Ok(records)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn detects_tampering_in_chain() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("audit.wal");
        let ledger = AuditLedger::new(&path).expect("ledger create");

        ledger
            .append_event("a1", "submitted", &serde_json::json!({"a":1}), "system")
            .expect("append 1");
        ledger
            .append_event("a1", "executed", &serde_json::json!({"ok":true}), "system")
            .expect("append 2");

        let content = fs::read_to_string(&path).expect("read wal");
        let tampered = content.replacen("executed", "tampered", 1);
        fs::write(&path, tampered).expect("tamper wal");

        let result = ledger.verify_chain();
        assert!(matches!(result, Err(LedgerError::ChainBroken(_))));
    }
}
