#![forbid(missing_docs, unsafe_code)]

use std::{
	fmt::Debug,
	hash::Hash,
	marker::PhantomData,
	pin::Pin,
	sync::Arc,
	time::{Instant},
};

use codec::{Codec, Decode, Encode};
use futures::{future::Either, prelude::*, Future, TryFutureExt};
use futures_timer::Delay;
use log::{info, warn};
use sc_client_api::{backend::AuxStore, BlockOf};
use sc_consensus::{BlockImport, BlockImportParams, ForkChoiceStrategy, StateAction};
use sc_consensus_aura::{find_pre_digest, CompatibilityMode, standalone as aura_internal};
use sc_consensus_slots::{BackoffAuthoringBlocksStrategy, SlotInfo, StorageChanges};
pub use sc_consensus_slots::{SimpleSlotWorker, SlotProportion};
use sc_telemetry::{telemetry, TelemetryHandle, CONSENSUS_INFO};
use sp_api::{Core, ProvideRuntimeApi};
use sp_application_crypto::AppPublic;
use sp_blockchain::HeaderBackend;
use sp_consensus::{EnableProofRecording, BlockOrigin, Environment, Error as ConsensusError, Proposal, Proposer};
pub use sp_consensus_aura::{
	digests::CompatibleDigestItem,
	inherents::{InherentDataProvider, InherentType as AuraInherent, INHERENT_IDENTIFIER},
	AuraApi, ConsensusLog, SlotDuration, AURA_ENGINE_ID,
};
use sp_consensus_slots::Slot;
use sp_core::crypto::{ByteArray, Pair, Public};

use crate::{digest_provider, AuraId, LOG_TARGET};
use sp_keystore::KeystorePtr;
use sp_runtime::traits::{Block as BlockT, Header, Member, NumberFor};
use tracing::error;

type AuthorityId<P> = <P as Pair>::Public;

pub struct MoonsamaAuraWorker<C, E, I, P, SO, L, BS, N, DP> {
	client: Arc<C>,
	block_import: I,
	env: E,
	keystore: KeystorePtr,
	sync_oracle: SO,
	justification_sync_link: L,
	force_authoring: bool,
	backoff_authoring_blocks: Option<BS>,
	block_proposal_slot_portion: SlotProportion,
	max_block_proposal_slot_portion: Option<SlotProportion>,
	telemetry: Option<TelemetryHandle>,
	compatibility_mode: CompatibilityMode<N>,
	additional_digests_provider: Arc<DP>,
	_key_type: PhantomData<P>,
}

#[async_trait::async_trait]
impl<B, C, E, I, P, Error, SO, L, BS, DP> sc_consensus_slots::SimpleSlotWorker<B>
	for MoonsamaAuraWorker<C, E, I, P, SO, L, BS, NumberFor<B>, DP>
where
	B: BlockT,
	C: ProvideRuntimeApi<B> + BlockOf + HeaderBackend<B> + Sync,
	C::Api: AuraApi<B, AuthorityId<P>>,
	E: Environment<B, Error = Error> + Send + Sync,
	E::Proposer: Proposer<
		B,
		Error = Error,
		ProofRecording = EnableProofRecording,
		Proof = <EnableProofRecording as ProofRecording>::Proof,
	>,
	I: BlockImport<B> + Send + Sync + 'static,
	P: Pair + Send + Sync,
	P::Public: AppPublic + Public + Member + Encode + Decode + Hash,
	P::Signature: TryFrom<Vec<u8>> + Member + Encode + Decode + Hash + Debug,
	SO: SyncOracle + Send + Clone + Sync,
	L: sc_consensus::JustificationSyncLink<B>,
	BS: BackoffAuthoringBlocksStrategy<NumberFor<B>> + Send + Sync + 'static,
	Error: std::error::Error + Send + From<sp_consensus::Error> + 'static,
	DP: digest_provider::DigestsProvider<AuraId, <B as BlockT>::Hash> + Send + Sync + 'static,
{
	type BlockImport = I;
	type SyncOracle = SO;
	type JustificationSyncLink = L;
	type CreateProposer =
		Pin<Box<dyn Future<Output = Result<E::Proposer, sp_consensus::Error>> + Send + 'static>>;
	type Proposer = E::Proposer;
	type Claim = P::Public;
	type AuxData = Vec<AuthorityId<P>>;

	fn logging_target(&self) -> &'static str {
		"aura"
	}

	fn block_import(&mut self) -> &mut Self::BlockImport {
		&mut self.block_import
	}

	fn aux_data(
		&self,
		header: &B::Header,
		_slot: Slot,
	) -> Result<Self::AuxData, sp_consensus::Error> {
		authorities(
			self.client.as_ref(),
			header.hash(),
			*header.number() + 1u32.into(),
			&self.compatibility_mode,
		)
	}

	fn authorities_len(&self, epoch_data: &Self::AuxData) -> Option<usize> {
		Some(epoch_data.len())
	}

	async fn claim_slot(
		&self,
		_header: &B::Header,
		slot: Slot,
		authorities: &Self::AuxData,
	) -> Option<Self::Claim> {
		aura_internal::claim_slot::<P>(slot, authorities, &self.keystore).await
	}

	fn pre_digest_data(&self, slot: Slot, _claim: &Self::Claim) -> Vec<sp_runtime::DigestItem> {
		vec![aura_internal::pre_digest::<P>(slot)]
	}

	async fn block_import_params(
		&self,
		header: B::Header,
		header_hash: &B::Hash,
		body: Vec<B::Extrinsic>,
		storage_changes: StorageChanges<<Self::BlockImport as BlockImport<B>>::Transaction, B>,
		public: Self::Claim,
		_authorities: Self::AuxData,
	) -> Result<
		sc_consensus::BlockImportParams<B, <Self::BlockImport as BlockImport<B>>::Transaction>,
		ConsensusError,
	> {
		let signature_digest_item =
			aura_internal::seal::<_, P>(header_hash, &public, &self.keystore)?;

		let mut import_block = BlockImportParams::new(BlockOrigin::Own, header);
		import_block.post_digests.push(signature_digest_item);
		import_block.body = Some(body);
		import_block.state_action =
			StateAction::ApplyChanges(sc_consensus::StorageChanges::Changes(storage_changes));
		import_block.fork_choice = Some(ForkChoiceStrategy::LongestChain);

		Ok(import_block)
	}

	fn force_authoring(&self) -> bool {
		self.force_authoring
	}

	fn should_backoff(&self, slot: Slot, chain_head: &B::Header) -> bool {
		if let Some(ref strategy) = self.backoff_authoring_blocks {
			if let Ok(chain_head_slot) = find_pre_digest::<B, P::Signature>(chain_head) {
				return strategy.should_backoff(
					*chain_head.number(),
					chain_head_slot,
					self.client.info().finalized_number,
					slot,
					self.logging_target(),
				)
			}
		}
		false
	}

	fn sync_oracle(&mut self) -> &mut Self::SyncOracle {
		&mut self.sync_oracle
	}

	fn justification_sync_link(&mut self) -> &mut Self::JustificationSyncLink {
		&mut self.justification_sync_link
	}

	fn proposer(&mut self, block: &B::Header) -> Self::CreateProposer {
		self.env
			.init(block)
			.map_err(|e| sp_consensus::Error::ClientImport(format!("{:?}", e)))
			.boxed()
	}

	fn telemetry(&self) -> Option<TelemetryHandle> {
		self.telemetry.clone()
	}

	fn proposing_remaining_duration(&self, slot_info: &SlotInfo<B>) -> std::time::Duration {
		let parent_slot = find_pre_digest::<B, P::Signature>(&slot_info.chain_head).ok();

		sc_consensus_slots::proposing_remaining_duration(
			parent_slot,
			slot_info,
			&self.block_proposal_slot_portion,
			self.max_block_proposal_slot_portion.as_ref(),
			sc_consensus_slots::SlotLenienceType::Exponential,
			self.logging_target(),
		)
	}

	/// Propose a block by `Proposer`.
	async fn propose(
		&mut self,
		proposer: Self::Proposer,
		claim: &Self::Claim,
		slot_info: SlotInfo<B>,
		end_proposing_at: Instant,
	) -> Option<
		Proposal<
			B,
			<Self::Proposer as Proposer<B>>::Transaction,
			<Self::Proposer as Proposer<B>>::Proof,
		>,
	> {
		let slot = slot_info.slot;
		let telemetry = self.telemetry();
		let log_target = self.logging_target();
		let proposing_remaining_duration =
			end_proposing_at.saturating_duration_since(Instant::now());

		let inherent_data =
			Self::create_inherent_data(&slot_info, &log_target, end_proposing_at).await?;

		let aura_id = AuraId::from_slice(&claim.as_slice())
			.map_err(|e| error!(target: LOG_TARGET, error = ?e, "Invalid Aura ID (wrong length)."))
			.ok()?;

		let mut logs = self.pre_digest_data(slot, claim);
		logs.extend(
			self.additional_digests_provider
				.provide_digests(aura_id, slot_info.chain_head.hash()),
		);

		// deadline our production to 98% of the total time left for proposing. As we deadline
		// the proposing below to the same total time left, the 2% margin should be enough for
		// the result to be returned.
		let proposing = proposer
			.propose(
				inherent_data,
				sp_runtime::generic::Digest { logs },
				proposing_remaining_duration.mul_f32(0.98),
				slot_info.block_size_limit,
			)
			.map_err(|e| sp_consensus::Error::ClientImport(e.to_string()));

		let proposal = match futures::future::select(
			proposing,
			Delay::new(proposing_remaining_duration),
		)
		.await
		{
			Either::Left((Ok(p), _)) => p,
			Either::Left((Err(err), _)) => {
				warn!(target: log_target, "Proposing failed: {}", err);

				return None
			},
			Either::Right(_) => {
				info!(
					target: log_target,
					"⌛️ Discarding proposal for slot {}; block production took too long", slot,
				);
				// If the node was compiled with debug, tell the user to use release optimizations.
				#[cfg(build_type = "debug")]
				info!(
					target: log_target,
					"👉 Recompile your node in `--release` mode to mitigate this problem.",
				);
				telemetry!(
					telemetry;
					CONSENSUS_INFO;
					"slots.discarding_proposal_took_too_long";
					"slot" => *slot,
				);

				return None
			},
		};

		Some(proposal)
	}
}

fn authorities<A, B, C>(
	client: &C,
	parent_hash: B::Hash,
	context_block_number: NumberFor<B>,
	compatibility_mode: &CompatibilityMode<NumberFor<B>>,
) -> Result<Vec<A>, ConsensusError>
where
	A: Codec + Debug,
	B: BlockT,
	C: ProvideRuntimeApi<B>,
	C::Api: AuraApi<B, A>,
{
	let runtime_api = client.runtime_api();

	match compatibility_mode {
		CompatibilityMode::None => {},
		// Use `initialize_block` until we hit the block that should disable the mode.
		CompatibilityMode::UseInitializeBlock { until } =>
			if *until > context_block_number {
				runtime_api
					.initialize_block(
						parent_hash,
						&B::Header::new(
							context_block_number,
							Default::default(),
							Default::default(),
							parent_hash,
							Default::default(),
						),
					)
					.map_err(|_| sp_consensus::Error::InvalidAuthoritiesSet)?;
			},
	}

	runtime_api
		.authorities(parent_hash)
		.ok()
		.ok_or(sp_consensus::Error::InvalidAuthoritiesSet)
}

/// Parameters of [`build_moonsama_aura_worker`].
pub struct BuildMoonsamaAuraWorkerParams<C, I, PF, SO, L, BS, N, DP> {
	/// The client to interact with the chain.
	pub client: Arc<C>,
	/// The block import.
	pub block_import: I,
	/// The proposer factory to build proposer instances.
	pub proposer_factory: PF,
	/// The sync oracle that can give us the current sync status.
	pub sync_oracle: SO,
	/// Hook into the sync module to control the justification sync process.
	pub justification_sync_link: L,
	/// Should we force the authoring of blocks?
	pub force_authoring: bool,
	/// The backoff strategy when we miss slots.
	pub backoff_authoring_blocks: Option<BS>,
	/// The keystore used by the node.
	pub keystore: KeystorePtr,
	/// The proportion of the slot dedicated to proposing.
	///
	/// The block proposing will be limited to this proportion of the slot from the starting of the
	/// slot. However, the proposing can still take longer when there is some lenience factor
	/// applied, because there were no blocks produced for some slots.
	pub block_proposal_slot_portion: SlotProportion,
	/// The maximum proportion of the slot dedicated to proposing with any lenience factor applied
	/// due to no blocks being produced.
	pub max_block_proposal_slot_portion: Option<SlotProportion>,
	/// Telemetry instance used to report telemetry metrics.
	pub telemetry: Option<TelemetryHandle>,
	/// Compatibility mode that should be used.
	///
	/// If in doubt, use `Default::default()`.
	pub compatibility_mode: CompatibilityMode<N>,
	/// Provide additional PreRuntime Digest
	pub additional_digests_provider: Arc<DP>,
}

/// Build the moonsama aura worker.
///
/// The caller is responsible for running this worker, otherwise it will do nothing.
pub fn build_moonsama_aura_worker<P, B, C, PF, I, SO, L, BS, DP, Error>(
	BuildMoonsamaAuraWorkerParams {
		client,
		block_import,
		proposer_factory,
		sync_oracle,
		justification_sync_link,
		backoff_authoring_blocks,
		keystore,
		block_proposal_slot_portion,
		max_block_proposal_slot_portion,
		telemetry,
		force_authoring,
		compatibility_mode,
		additional_digests_provider,
	}: BuildMoonsamaAuraWorkerParams<C, I, PF, SO, L, BS, NumberFor<B>, DP>,
) -> impl sc_consensus_slots::SimpleSlotWorker<
	B,
	Proposer = PF::Proposer,
	BlockImport = I,
	SyncOracle = SO,
	JustificationSyncLink = L,
	Claim = P::Public,
	AuxData = Vec<AuthorityId<P>>,
>
where
	B: BlockT,
	C: ProvideRuntimeApi<B> + BlockOf + AuxStore + HeaderBackend<B> + Send + Sync,
	C::Api: AuraApi<B, AuthorityId<P>>,
	PF: Environment<B, Error = Error> + Send + Sync + 'static,
	PF::Proposer: Proposer<
		B,
		Error = Error,
		ProofRecording = EnableProofRecording,
		Proof = <EnableProofRecording as ProofRecording>::Proof,
	>,
	P: Pair + Send + Sync,
	P::Public: AppPublic + Hash + Member + Encode + Decode,
	P::Signature: TryFrom<Vec<u8>> + Hash + Member + Encode + Decode,
	I: BlockImport<B> + Send + Sync + 'static,
	Error: std::error::Error + Send + From<sp_consensus::Error> + 'static,
	SO: SyncOracle + Send + Sync + Clone,
	L: sc_consensus::JustificationSyncLink<B>,
	BS: BackoffAuthoringBlocksStrategy<NumberFor<B>> + Send + Sync + 'static,
	DP: digest_provider::DigestsProvider<AuraId, <B as BlockT>::Hash> + Send + Sync + 'static,
{
	MoonsamaAuraWorker {
		client,
		block_import,
		env: proposer_factory,
		keystore,
		sync_oracle,
		justification_sync_link,
		force_authoring,
		backoff_authoring_blocks,
		telemetry,
		block_proposal_slot_portion,
		max_block_proposal_slot_portion,
		compatibility_mode,
		additional_digests_provider,
		_key_type: PhantomData::<P>,
	}
}

// TODO: add tests
