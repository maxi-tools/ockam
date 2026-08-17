use cfg_if::cfg_if;

use ockam_core::compat::sync::Arc;
use ockam_core::compat::vec::Vec;
use ockam_core::flow_control::{FlowControlId, FlowControlOutgoingAccessControl, FlowControls};
use ockam_core::{Address, OutgoingAccessControl, Result};

use crate::models::CredentialAndPurposeKey;
use crate::secure_channel::Addresses;
use crate::{
    CredentialRetrieverCreator, Identifier, IdentityError, MemoryCredentialRetrieverCreator,
    TrustEveryonePolicy, TrustPolicy,
};

use core::fmt;
use core::fmt::Formatter;
use core::time::Duration;
#[cfg(feature = "std")]
use ockam_core::env::get_env_with_default;

/// This is the default timeout for creating a secure channel
pub(super) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// Environment variable name for changing the default timeout used to create secure channels
/// or make a request
pub const OCKAM_DEFAULT_TIMEOUT: &str = "OCKAM_DEFAULT_TIMEOUT";

/// Trust options for a Secure Channel
pub struct SecureChannelOptions {
    pub(crate) flow_control_id: FlowControlId,
    pub(crate) trust_policy: Arc<dyn TrustPolicy>,
    // To verify other party's credentials
    pub(crate) authority: Option<Identifier>,
    // To obtain our credentials
    pub(crate) credential_retriever_creator: Option<Arc<dyn CredentialRetrieverCreator>>,
    pub(crate) timeout: Duration,
    pub(crate) key_exchange_only: bool,
    // Secure Channel will be persisted (currently only supported for key_exchange_only = true)
    pub(crate) is_persistent: bool,
}

impl fmt::Debug for SecureChannelOptions {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "FlowId: {}", self.flow_control_id)
    }
}

impl SecureChannelOptions {
    /// Mark this Secure Channel Decryptor as a Producer with a random [`FlowControlId`]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            flow_control_id: FlowControls::generate_flow_control_id(),
            trust_policy: Arc::new(TrustEveryonePolicy),
            authority: None,
            credential_retriever_creator: None,
            timeout: DEFAULT_TIMEOUT,
            key_exchange_only: false,
            is_persistent: false,
        }
    }

    /// Sets a timeout different from the default one [`DEFAULT_TIMEOUT`]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set [`CredentialRetrieverCreator`]
    pub fn with_credential_retriever_creator(
        mut self,
        credential_retriever_creator: Arc<dyn CredentialRetrieverCreator>,
    ) -> Result<Self> {
        if self.credential_retriever_creator.is_some() {
            return Err(IdentityError::CredentialRetrieverCreatorAlreadySet.into());
        }
        self.credential_retriever_creator = Some(credential_retriever_creator);
        Ok(self)
    }

    /// Set credential
    pub fn with_credential(self, credential: CredentialAndPurposeKey) -> Result<Self> {
        self.with_credential_retriever_creator(Arc::new(MemoryCredentialRetrieverCreator::new(
            credential,
        )))
    }

    /// Sets Trusted Authority
    pub fn with_authority(mut self, authority: Identifier) -> Self {
        self.authority = Some(authority);
        self
    }

    /// Set Trust Policy
    pub fn with_trust_policy(mut self, trust_policy: impl TrustPolicy) -> Self {
        self.trust_policy = Arc::new(trust_policy);
        self
    }

    /// Freshly generated [`FlowControlId`]
    pub fn producer_flow_control_id(&self) -> FlowControlId {
        self.flow_control_id.clone()
    }

    /// The secure channel will be used to exchange keys only. Application data is
    /// then encrypted and decrypted through the api addresses rather than routed
    /// through the channel.
    ///
    /// # This turns off two security properties. Read before using.
    ///
    /// The name says what the mode is *for*, not what it costs, and the cost is
    /// not small. Measured against this source on 2026-08-17:
    ///
    /// - `DecryptorHandler::new` selects [`Decryptor::new_naive`] when this is
    ///   set, which sets `nonce_tracker: None`. **There is no replay window and
    ///   no replay rejection.** A captured ciphertext decrypts again, and again.
    /// - `HandshakeWorker` passes `rekeying: false` to the `Encryptor`, so the
    ///   channel key is never rotated. **No forward-secrecy ratchet.**
    ///
    /// Neither is mentioned by the mode's purpose, and both are exactly what a
    /// caller reaching for "key exchange only" is least likely to be asking for.
    /// The method is named for its cost so that reaching for it is a decision
    /// rather than an accident.
    ///
    /// If you want the oracle without giving these up, do not set this: the api
    /// addresses work in the default mode too. That is what maxi-transport's
    /// bridge does.
    ///
    /// Renamed from `key_exchange_only` in the maxi-tools fork. Upstream
    /// `build-trust/ockam` still calls it `key_exchange_only`.
    pub fn key_exchange_only_without_replay_protection(mut self) -> Self {
        self.key_exchange_only = true;
        self
    }

    /// Secure Channel will be persisted after a successful handshake
    /// NOTE: Currently only supported after key_exchange_only_without_replay_protection()
    pub fn persist(mut self) -> Result<Self> {
        if !self.key_exchange_only {
            return Err(IdentityError::PersistentSupportIsLimited.into());
        }
        self.is_persistent = true;
        Ok(self)
    }
}

impl SecureChannelOptions {
    pub(crate) fn setup_flow_control_producer(
        flow_control_id: &FlowControlId,
        flow_controls: &FlowControls,
        addresses: &Addresses,
    ) {
        flow_controls.add_producer(
            &addresses.decryptor_internal,
            flow_control_id,
            None,
            vec![addresses.encryptor.clone()],
        );
    }

    pub(crate) fn setup_flow_control_consumer(
        flow_controls: &FlowControls,
        addresses: &Addresses,
        next: &Address,
    ) {
        if let Some(flow_control_id) = flow_controls
            .find_flow_control_with_producer_address(next)
            .map(|x| x.flow_control_id().clone())
        {
            // Allow a sender with corresponding flow_control_id send messages to this address
            flow_controls.add_consumer(&addresses.decryptor_remote, &flow_control_id);
        }
    }

    pub(crate) fn setup_flow_control(
        &self,
        flow_controls: &FlowControls,
        addresses: &Addresses,
        next: &Address,
    ) {
        Self::setup_flow_control_consumer(flow_controls, addresses, next);
        Self::setup_flow_control_producer(&self.flow_control_id, flow_controls, addresses);
    }

    pub(crate) fn create_decryptor_outgoing_access_control(
        &self,
        flow_controls: &FlowControls,
    ) -> Arc<dyn OutgoingAccessControl> {
        let ac = FlowControlOutgoingAccessControl::new(
            flow_controls,
            self.flow_control_id.clone(),
            None,
        );

        Arc::new(ac)
    }
}

/// Trust options for a Secure Channel Listener
pub struct SecureChannelListenerOptions {
    pub(crate) consumer: Vec<FlowControlId>,
    pub(crate) flow_control_id: FlowControlId,
    pub(crate) trust_policy: Arc<dyn TrustPolicy>,
    // To verify other party's credentials
    pub(crate) authority: Option<Identifier>,
    // To obtain our credentials
    pub(crate) credential_retriever_creator: Option<Arc<dyn CredentialRetrieverCreator>>,
    pub(crate) key_exchange_only: bool,
    // Secure Channel will be persisted (currently only supported for key_exchange_only = true)
    pub(crate) is_persistent: bool,
}

impl fmt::Debug for SecureChannelListenerOptions {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "SpawnerFlowId: {}", self.flow_control_id)
    }
}

impl SecureChannelListenerOptions {
    /// Mark spawned Secure Channel Decryptors as Producers for a given Spawner's [`FlowControlId`]
    /// NOTE: Spawned connections get fresh random [`FlowControlId`], however they are still marked
    /// with Spawner's [`FlowControlId`]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            consumer: vec![],
            flow_control_id: FlowControls::generate_flow_control_id(),
            trust_policy: Arc::new(TrustEveryonePolicy),
            authority: None,
            credential_retriever_creator: None,
            key_exchange_only: false,
            is_persistent: false,
        }
    }

    /// Mark that this Secure Channel Listener is a Consumer for to the given [`FlowControlId`]
    /// Also, in this case spawned Secure Channels will be marked as Consumers with [`FlowControlId`]
    /// of the message that was used to create the Secure Channel
    pub fn as_consumer(mut self, id: &FlowControlId) -> Self {
        self.consumer.push(id.clone());

        self
    }

    /// Set [`CredentialRetrieverCreator`]
    pub fn with_credential_retriever_creator(
        mut self,
        credential_retriever_creator: Arc<dyn CredentialRetrieverCreator>,
    ) -> Result<Self> {
        if self.credential_retriever_creator.is_some() {
            return Err(IdentityError::CredentialRetrieverCreatorAlreadySet.into());
        }
        self.credential_retriever_creator = Some(credential_retriever_creator);
        Ok(self)
    }

    /// Set credential
    pub fn with_credential(self, credential: CredentialAndPurposeKey) -> Result<Self> {
        self.with_credential_retriever_creator(Arc::new(MemoryCredentialRetrieverCreator::new(
            credential,
        )))
    }

    /// Sets Trusted Authority
    pub fn with_authority(mut self, authority: Identifier) -> Self {
        self.authority = Some(authority);
        self
    }

    /// Set trust policy
    pub fn with_trust_policy(mut self, trust_policy: impl TrustPolicy) -> Self {
        self.trust_policy = Arc::new(trust_policy);
        self
    }

    /// Freshly generated [`FlowControlId`]
    pub fn spawner_flow_control_id(&self) -> FlowControlId {
        self.flow_control_id.clone()
    }

    /// The secure channel will be used to exchange keys only. Application data is
    /// then encrypted and decrypted through the api addresses rather than routed
    /// through the channel.
    ///
    /// # This turns off two security properties. Read before using.
    ///
    /// The name says what the mode is *for*, not what it costs, and the cost is
    /// not small. Measured against this source on 2026-08-17:
    ///
    /// - `DecryptorHandler::new` selects [`Decryptor::new_naive`] when this is
    ///   set, which sets `nonce_tracker: None`. **There is no replay window and
    ///   no replay rejection.** A captured ciphertext decrypts again, and again.
    /// - `HandshakeWorker` passes `rekeying: false` to the `Encryptor`, so the
    ///   channel key is never rotated. **No forward-secrecy ratchet.**
    ///
    /// Neither is mentioned by the mode's purpose, and both are exactly what a
    /// caller reaching for "key exchange only" is least likely to be asking for.
    /// The method is named for its cost so that reaching for it is a decision
    /// rather than an accident.
    ///
    /// If you want the oracle without giving these up, do not set this: the api
    /// addresses work in the default mode too. That is what maxi-transport's
    /// bridge does.
    ///
    /// Renamed from `key_exchange_only` in the maxi-tools fork. Upstream
    /// `build-trust/ockam` still calls it `key_exchange_only`.
    pub fn key_exchange_only_without_replay_protection(mut self) -> Self {
        self.key_exchange_only = true;
        self
    }

    /// Secure Channel will be persisted after a successful handshake
    /// NOTE: Currently only supported after key_exchange_only_without_replay_protection()
    pub fn persist(mut self) -> Result<Self> {
        if !self.key_exchange_only {
            return Err(IdentityError::PersistentSupportIsLimited.into());
        }
        self.is_persistent = true;
        Ok(self)
    }
}

impl SecureChannelListenerOptions {
    pub(crate) fn setup_flow_control_for_listener(
        &self,
        flow_controls: &FlowControls,
        address: &Address,
    ) {
        for id in &self.consumer {
            flow_controls.add_consumer(address, id);
        }

        flow_controls.add_spawner(address, &self.flow_control_id);
    }

    pub(crate) fn setup_flow_control_for_channel(
        &self,
        flow_controls: &FlowControls,
        listener_address: &Address,
        addresses: &Addresses,
    ) -> FlowControlId {
        // Add decryptor as consumer for the same ids as the listener, so that even if the initiator
        // updates the route - decryptor is still reachable
        for id in flow_controls.get_flow_control_ids_for_consumer(listener_address) {
            flow_controls.add_consumer(&addresses.decryptor_remote, &id);
        }

        // TODO: What if we added a listener as a consumer for new FlowControlIds, should existing
        //  secure channels be accessible through these new ids?
        //  Consider following flow:
        //   1. You have a secure channel listener listener1 accessible from a tcp listener tcp1.
        //   2. A secure channel sc1 is established
        //   3. You start TcpListener tcp2
        //   4. You make existing listener1 accessible from tcp2
        //  Should sc1 now be accessible from tcp2? In current implementation it won't be. That's something to consider

        let flow_control_id = FlowControls::generate_flow_control_id();
        flow_controls.add_producer(
            &addresses.decryptor_internal,
            &flow_control_id,
            Some(&self.flow_control_id),
            vec![addresses.encryptor.clone()],
        );

        flow_control_id
    }

    pub(crate) fn create_decryptor_outgoing_access_control(
        &self,
        flow_controls: &FlowControls,
        flow_control_id: FlowControlId,
    ) -> Arc<dyn OutgoingAccessControl> {
        let ac = FlowControlOutgoingAccessControl::new(
            flow_controls,
            flow_control_id,
            Some(self.flow_control_id.clone()),
        );

        Arc::new(ac)
    }
}

/// Return a default timeout for creating secure channels or make a request
pub fn get_default_timeout() -> Duration {
    cfg_if! {
        if #[cfg(feature = "std")] {
            get_env_with_default::<Duration>(OCKAM_DEFAULT_TIMEOUT, DEFAULT_TIMEOUT)
              .ok()
              .unwrap_or(DEFAULT_TIMEOUT)
        } else {
            DEFAULT_TIMEOUT
        }
    }
}
