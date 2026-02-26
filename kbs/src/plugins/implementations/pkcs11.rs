// Copyright (c) 2025 IBM and Red Hat.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! This module provides plugin support for the cryptographic backend.
//!
//! For more information about PKCS_11 and the methodologies used, see the following
//! * [PKCS_11 Usage Guide](<https://docs.oasis-open.org/pkcs11/pkcs11-ug/v3.2/pkcs11-ug-v3.2.html>)
//! * [PKCS_11 Specification v3.0](<https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html>)
//! * [PKCS_11 Base Specification v3.0](<https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html>)
use crate::plugins::resource::{ResourceDesc, StorageBackend};
use actix_web::http::Method;
use anyhow::{anyhow, bail, Context, Result};
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::{
        rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource},
        Mechanism, MechanismType,
    },
    object::{Attribute, AttributeInfo, AttributeType, KeyType, ObjectClass},
    session::{Session, UserType},
    types::AuthPin,
};
use educe::Educe;
use serde::Deserialize;
use std::{
    cell::RefCell,
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, OnceLock},
    thread,
};

use super::super::plugin_manager::ClientPlugin;

// Session is Send but NOT Sync: it can be moved between threads
// but cannot be shared. Each thread must have its own Session instance.
thread_local! {
    static PKCS11_SESSION: RefCell<Option<Session>> = const { RefCell::new(None) };
}
static PKCS11_CTX: OnceLock<Pkcs11> = OnceLock::new();

/// Enum representing supported RSA mechanisms.
#[derive(Educe, Deserialize, Clone, PartialEq, Default)]
#[educe(Debug)]
pub enum RsaMechanism {
    /// RSA mechanism using PKCS#1 OAEP MGF1_SHA256 padding. Recommended for secure production use.
    #[default]
    RsaPkcsOaep,
    /// RSA mechanism using PKCS#1 v1.5 with MGF1_SHA1 padding.
    ///
    /// ⚠️ This mechanism relies on SHA-1, which is considered deprecated and insecure.
    /// It should only be used for testing or legacy compatibility purposes.    
    RsaPkcsTest,
}

impl RsaMechanism {
    /// Converts the enum variant into a corresponding PKCS#11 mechanism.
    pub fn to_pkcs11_mechanism(&self) -> Mechanism<'_> {
        match self {
            RsaMechanism::RsaPkcsOaep => Mechanism::RsaPkcsOaep(PkcsOaepParams::new(
                MechanismType::SHA256,
                PkcsMgfType::MGF1_SHA256,
                PkcsOaepSource::empty(),
            )),
            RsaMechanism::RsaPkcsTest => Mechanism::RsaPkcsOaep(PkcsOaepParams::new(
                MechanismType::SHA1,
                PkcsMgfType::MGF1_SHA1,
                PkcsOaepSource::empty(),
            )),
        }
    }
}

#[derive(Educe, Deserialize, Clone, PartialEq)]
#[educe(Debug)]
pub struct Pkcs11Config {
    /// Path to the PKCS11 module.
    module: PathBuf,

    /// The index of the slot to be used. If not provided, the first slot will be used.
    #[serde(default)]
    slot_index: u8,

    /// The user pin for authenticating the session.
    #[educe(Debug(ignore))]
    pin: String,

    /// RSA mechanism to use.
    #[serde(default)]
    rsa_mechanism: RsaMechanism,

    /// String used to lookup private or public key for cryptographic operations
    #[serde(default)]
    lookup_label: String,
}

pub struct Pkcs11Backend {
    slot: cryptoki::slot::Slot,
    pin: String,
    lookup_label: String,
    rsa_mechanism: Arc<RsaMechanism>,
}

impl Drop for Pkcs11Backend {
    fn drop(&mut self) {
        if PKCS11_CTX.get().is_some() {
            let pkcs11 = PKCS11_CTX
                .get()
                .context("PKCS11 context not initialized")
                .unwrap()
                .clone();
            let _ = pkcs11.finalize();
            println!("pkcs11 finalized and closed");
        }
    }
}

impl TryFrom<Pkcs11Config> for Pkcs11Backend {
    type Error = anyhow::Error;

    fn try_from(config: Pkcs11Config) -> Result<Self> {
        let pkcs11 = Pkcs11::new(&config.module).context("unable to open pkcs11 module")?;
        pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;

        let slots = pkcs11.get_slots_with_token()?;
        let slot_index = usize::from(config.slot_index);

        PKCS11_CTX
            .set(pkcs11)
            .expect("PKCS11 context already initialized");

        if slot_index >= slots.len() {
            bail!("Slot index out of range");
        }

        Ok(Self {
            slot: slots[slot_index],
            pin: config.pin,
            lookup_label: config.lookup_label,
            rsa_mechanism: Arc::new(config.rsa_mechanism),
        })
    }
}

impl Pkcs11Backend {
    fn open_authenticated_session(&self) -> Result<Session> {
        let pkcs11 = PKCS11_CTX.get().expect("PKCS11 not initialized");

        let session = pkcs11.open_rw_session(self.slot)?;
        let user_pin = AuthPin::new(self.pin.clone().into_boxed_str());
        session.login(UserType::User, Some(&user_pin))?;
        Ok(session)
    }

    fn with_session<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&Session) -> Result<R>,
    {
        PKCS11_SESSION.with(|session_cell| {
            let mut session_opt = session_cell.borrow_mut();

            // Validate existing session by checking get_session_info().
            // If this returns an error, the session handle is no longer valid.
            let needs_reopen = session_opt
                .as_ref()
                .map(|s| {
                    let session_info = s.get_session_info();
                    println!(
                        "Thread {:?}: Session info check: {:?}",
                        thread::current().id(),
                        session_info
                    );
                    session_info.is_err()
                })
                .unwrap_or(true);

            if needs_reopen {
                // Explicitly set to None to trigger Drop on the old session.
                // This ensures C_CloseSession is called before opening a new session.
                *session_opt = None;

                // Open new session (R/W)
                
                let new_session = self.open_authenticated_session()?;



                println!("Thread {:?}: Opened new RW session", thread::current().id());

                // Store in thread-local storage
                *session_opt = Some(new_session);
            } else {
                println!(
                    "Thread {:?}: Reusing existing session",
                    thread::current().id()
                );
            }

            // Execute closure with session reference
            let session_ref = session_opt.as_ref().expect("Session should exist");
            f(session_ref)
        })
    }
}

#[async_trait::async_trait]
impl ClientPlugin for Pkcs11Backend {
    async fn handle(
        &self,
        body: &[u8],
        _query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
    ) -> Result<Vec<u8>> {
        let desc = path.join("/");

        match &desc[..] {
            "wrap-key" => self.wrap_key_handle(body, method).await,
            _ => {
                let (action, params) = desc.split_once('/').context("accessed path is invalid")?;
                match action {
                    "resource" => self.resource_handle(params, body, method).await,
                    _ => bail!("invalid path"),
                }
            }
        }
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        _path: &[&str],
        method: &Method,
    ) -> Result<bool> {
        match *method {
            Method::GET => Ok(false),
            Method::POST => Ok(true),
            _ => bail!("invalid method"),
        }
    }

    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        _path: &[&str],
        _method: &Method,
    ) -> Result<bool> {
        Ok(true)
    }
}

#[async_trait::async_trait]
impl StorageBackend for Pkcs11Backend {
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        self.with_session(|session| {
            let attributes = vec![Attribute::Label(Vec::from(resource_desc.to_string()))];
            let objects = session.find_objects(&attributes)?;

            if objects.is_empty() {
                bail!("Could not find object with label {}", resource_desc);
            }

            let object = objects[0];

            let value_attribute = vec![AttributeType::Value];
            let attribute_map = session.get_attribute_info_map(object, &value_attribute)?;

            let Some(AttributeInfo::Available(_)) = attribute_map.get(&AttributeType::Value) else {
                bail!("Key does not have value attribute available.");
            };

            let attrs = session.get_attributes(object, &value_attribute)?;
            let Attribute::Value(bytes) =
                attrs.first().ok_or(anyhow!("empty attributes returned"))?
            else {
                bail!("Failed to get value.");
            };

            Ok(bytes.clone())
        })
    }

    async fn write_secret_resource(&self, resource_desc: ResourceDesc, data: &[u8]) -> Result<()> {
        self.with_session(|session| {
            let attributes = vec![
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::GENERIC_SECRET),
                Attribute::Extractable(true),
                Attribute::Private(true),
                Attribute::Value(data.to_vec()),
                Attribute::Label(Vec::from(resource_desc.to_string())),
            ];

            session.create_object(&attributes)?;
            Ok(())
        })
    }
}

impl Pkcs11Backend {
    async fn resource_handle(&self, tag: &str, body: &[u8], method: &Method) -> Result<Vec<u8>> {
        let tag = ResourceDesc::try_from(tag).context("invalid path")?;

        match *method {
            Method::GET => self.read_secret_resource(tag).await,
            Method::POST => {
                self.write_secret_resource(tag, body).await?;
                Ok(vec![])
            }
            _ => bail!("Illegal HTTP method. Only supports `GET` and `POST`"),
        }
    }

    async fn wrap_key_handle(&self, body: &[u8], method: &Method) -> Result<Vec<u8>> {
        match *method {
            Method::POST => self.wrapkey_wrap(body).await,
            Method::GET => self.wrapkey_unwrap(body).await,
            _ => bail!("invalid method"),
        }
    }

    async fn wrapkey_wrap(&self, body: &[u8]) -> Result<Vec<u8>> {
        self.with_session(|session| {
            let pubkey_template = vec![
                Attribute::Label(self.lookup_label.clone().into()),
                Attribute::Class(ObjectClass::PUBLIC_KEY),
            ];

            let mut pubkey = session
                .find_objects(&pubkey_template)
                .context("unable to find public wrap key in PKCS11 module")?;

            let encrypted = session
                .encrypt(
                    &self.rsa_mechanism.to_pkcs11_mechanism(),
                    pubkey.remove(0),
                    body,
                )
                .context("unable to encrypt HTTP body with public wrap key")?;

            Ok(encrypted)
        })
    }

    async fn wrapkey_unwrap(&self, body: &[u8]) -> Result<Vec<u8>> {
        self.with_session(|session| {
            let privkey_template = vec![
                Attribute::Label(self.lookup_label.clone().into()),
                Attribute::Class(ObjectClass::PRIVATE_KEY),
            ];

            let mut privkey = session
                .find_objects(&privkey_template)
                .context("unable to find private wrap key in PKCS11 module")?;

            let decrypted = session
                .decrypt(
                    &self.rsa_mechanism.to_pkcs11_mechanism(),
                    privkey.remove(0),
                    body,
                )
                .context("unable to decrypt HTTP body with private wrap key")?;

            Ok(decrypted)
        })
    }
}
/// In general tests using softhsm has to run in a serial scope as they are session locked
#[cfg(test)]
mod tests {

    use crate::plugins::{
        pkcs11::{
            Pkcs11Backend, Pkcs11Config,
            RsaMechanism::{RsaPkcsOaep, RsaPkcsTest},
        },
        resource::backend::{ResourceDesc, StorageBackend},
    };
    use serial_test::serial;
    use std::{process::Command, sync::{Once, OnceLock}};

    static LOOKUP_LABEL: &'static str = "trustee-test";
    static HSM_USER_PIN: &'static str = "12345678";
    static SOFTHSM_PATH: &'static str = "/usr/lib/softhsm/libsofthsm2.so";

    static INIT: Once = Once::new();
    static BACKEND: OnceLock<Pkcs11Backend> = OnceLock::new();



    fn init_test_suite_once() {
        INIT.call_once(|| {
            let config = Pkcs11Config {
                module: SOFTHSM_PATH.into(),
                slot_index: 0,
                // This pin must be set for SoftHSM
                pin: HSM_USER_PIN.to_string(),
                rsa_mechanism: RsaPkcsTest,
                lookup_label: LOOKUP_LABEL.into(),
            };

            let backend = Pkcs11Backend::try_from(config).unwrap();
            
            let _ = BACKEND.set(backend);

           
        });

    }

    async fn before_test() {
        let status = Command::new("bash")
            .arg("test/script/plugin/pkcs11/".to_owned() + "generate_keypair_with_label.sh")
            .arg(LOOKUP_LABEL)
            .arg(HSM_USER_PIN)
            .arg(SOFTHSM_PATH)
            .status()
            .expect("failed to run setup script");
        assert!(status.success(), "setup script failed");
    }
    struct Teardown;
    impl Drop for Teardown {
        fn drop(&mut self) {
            // This will run even if the test panics
            let status = std::process::Command::new("bash")
                .arg("test/script/plugin/pkcs11/delete_by_label.sh")
                .arg(LOOKUP_LABEL)
                .arg(HSM_USER_PIN)
                .arg(SOFTHSM_PATH)
                .status()
                .expect("failed to run teardown script");

            assert!(status.success(), "teardown script failed");
        }
    }

    const TEST_DATA: &[u8] = b"testdata";

    // This will only work if SoftHSM is setup accordingly.
    #[tokio::test]
    #[serial]
    async fn write_and_read_resource() {
        init_test_suite_once();        
        let backend = BACKEND.get().unwrap();



        let resource_desc = ResourceDesc {
            repository_name: "default".into(),
            resource_type: "test".into(),
            resource_tag: "test".into(),
        };

        backend
            .write_secret_resource(resource_desc.clone(), TEST_DATA)
            .await
            .expect("write secret resource failed");
        let data = backend
            .read_secret_resource(resource_desc)
            .await
            .expect("read secret resource failed");

        assert_eq!(&data[..], TEST_DATA);
    }

    // This will only work is SoftHsm is setup accordingly.
    #[tokio::test]
    #[serial]
    async fn wrap_and_unwrap_data() {
        before_test().await;
        init_test_suite_once();
        
        

        let _teardown = Teardown;
        let backend = BACKEND.get().unwrap();

        let data = "TEST";

        let wrapped = backend.wrapkey_wrap(data.as_bytes()).await.unwrap();

        assert_ne!(data.as_bytes(), wrapped);

        let unwrapped = backend.wrapkey_unwrap(&wrapped).await.unwrap();

        assert_eq!(data.as_bytes(), unwrapped);
    }

}
