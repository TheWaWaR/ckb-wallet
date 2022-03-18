use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use secp256k1::recovery::{RecoverableSignature, RecoveryId};

use ckb_sdk::bip32::DerivationPath;
use ckb_sdk::traits::{TransactionDependencyProvider, Wallet, WalletError};
use ckb_sdk::util::serialize_signature;
use ckb_sdk::SECP256K1;
use ckb_types::{bytes::Bytes, core::TransactionView, H160, H256};

use super::{KeyChain, KeyStore, KeyTimeout};

/// A wallet use filesystem keystore as backend.
pub struct FileSystemKeystoreWallet {
    pub keystore: Arc<Mutex<KeyStore>>,
    hd_ids: HashMap<H160, (DerivationPath, Option<KeyChain>)>,
}

impl FileSystemKeystoreWallet {
    pub fn new(keystore: KeyStore) -> FileSystemKeystoreWallet {
        let keystore = Arc::new(Mutex::new(keystore));
        FileSystemKeystoreWallet {
            keystore,
            hd_ids: HashMap::default(),
        }
    }
    pub fn lock(&self, hash160: &H160) -> bool {
        self.keystore.lock().lock(hash160)
    }
    pub fn unlock(&self, hash160: &H160, password: &[u8]) -> Result<KeyTimeout, WalletError> {
        self.keystore
            .lock()
            .unlock(hash160, password)
            .map_err(|err| WalletError::Other(err.into()))
    }
    pub fn cache_key_set(
        &mut self,
        hash160: &H160,
        external_len: u32,
        change_len: u32,
    ) -> Result<(), WalletError> {
        let mut keystore = self.keystore.lock();
        let ckb_root_opt = keystore.get_ckb_root(hash160, true);
        if ckb_root_opt.is_none() {
            self.hd_ids.remove(hash160);
        }
        let ckb_root = ckb_root_opt
            .ok_or_else(|| WalletError::Other("master key not found".to_string().into()))?;
        self.hd_ids
            .insert(hash160.clone(), (DerivationPath::empty(), None));

        let key_set = ckb_root.derived_key_set_by_index(0, external_len, 0, change_len);
        for (path, pubkey_hash) in key_set.external {
            self.hd_ids
                .insert(pubkey_hash, (path, Some(KeyChain::External)));
        }
        for (path, pubkey_hash) in key_set.change {
            self.hd_ids
                .insert(pubkey_hash, (path, Some(KeyChain::Change)));
        }
        Ok(())
    }
    fn get_id_info(&self, id: &[u8]) -> Option<(H160, DerivationPath, Option<KeyChain>)> {
        if id.len() != 16 {
            return None;
        }
        let mut buf = [0u8; 20];
        buf.copy_from_slice(id);
        let hash160 = H160::from(buf);
        if let Some((path, key_chain)) = self.hd_ids.get(&hash160) {
            return Some((hash160, path.clone(), *key_chain));
        }
        if self.keystore.lock().has_account(&hash160, true) {
            return Some((hash160, DerivationPath::empty(), None));
        }
        None
    }
}

impl Wallet for FileSystemKeystoreWallet {
    fn match_id(&self, id: &[u8]) -> bool {
        self.get_id_info(id).is_some()
    }

    fn sign(
        &self,
        id: &[u8],
        message: &[u8],
        recoverable: bool,
        _tx: &TransactionView,
        // This is mainly for hardware wallet.
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<Bytes, WalletError> {
        let (hash160, path, _key_chain) = self.get_id_info(id).ok_or(WalletError::IdNotFound)?;
        if message.len() != 32 {
            return Err(WalletError::InvalidMessage(format!(
                "expected: 32, got: {}",
                message.len()
            )));
        }
        let msg = {
            let mut msg_buf = [0u8; 32];
            msg_buf.copy_from_slice(message);
            H256::from(msg_buf)
        };

        if recoverable {
            self.keystore
                .lock()
                .sign_recoverable(&hash160, &path, &msg)
                .map(|signature| Bytes::from(serialize_signature(&signature).to_vec()))
                .map_err(|err| WalletError::Other(err.into()))
        } else {
            self.keystore
                .lock()
                .sign(&hash160, &path, &msg)
                .map(|signature| Bytes::from(signature.serialize_compact().to_vec()))
                .map_err(|err| WalletError::Other(err.into()))
        }
    }

    fn verify(
        &self,
        id: &[u8],
        message: &[u8],
        pubkey: Option<Bytes>,
        signature: Bytes,
    ) -> Result<Option<Bytes>, WalletError> {
        let _ = self.get_id_info(id).ok_or(WalletError::IdNotFound)?;
        if message.len() != 32 {
            return Err(WalletError::InvalidMessage(format!(
                "expected: 32, got: {}",
                message.len()
            )));
        }
        let msg = {
            let mut msg_buf = [0u8; 32];
            msg_buf.copy_from_slice(message);
            secp256k1::Message::from_slice(message).expect("Convert to message failed")
        };
        if let Some(pubkey) = pubkey {
            if signature.len() != 64 {
                return Err(WalletError::InvalidSignature(format!(
                    "expected: 64, got: {}",
                    signature.len()
                )));
            }
            let pubkey = secp256k1::PublicKey::from_slice(pubkey.as_ref())
                .map_err(|err| WalletError::Other(format!("invalid pubkey: {}", err).into()))?;
            let sig = secp256k1::Signature::from_compact(&signature)
                .map_err(|err| WalletError::InvalidSignature(err.to_string()))?;
            SECP256K1
                .verify(&msg, &sig, &pubkey)
                .map(|()| None)
                .map_err(|err| WalletError::Other(err.into()))
        } else {
            if signature.len() != 65 {
                return Err(WalletError::InvalidSignature(format!(
                    "expected: 65, got: {}",
                    signature.len()
                )));
            }
            let recov_id = RecoveryId::from_i32(i32::from(signature.as_ref()[64]))
                .map_err(|err| WalletError::InvalidSignature(err.to_string()))?;
            let sig = RecoverableSignature::from_compact(&signature.as_ref()[0..64], recov_id)
                .map_err(|err| WalletError::InvalidSignature(err.to_string()))?;
            SECP256K1
                .recover(&msg, &sig)
                .map(|pubkey| Some(Bytes::from(pubkey.serialize().to_vec())))
                .map_err(|err| WalletError::Other(err.into()))
        }
    }
}
