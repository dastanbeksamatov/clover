//! A collection of node-specific RPC methods.
//! Substrate provides the `sc-rpc` crate, which defines the core RPC layer
//! used by Substrate nodes. This file extends those RPC definitions with
//! capabilities that are specific to this project's runtime configuration.

#![warn(missing_docs)]
use std::sync::Arc;

use std::collections::BTreeMap;
use clover_primitives::{Block, BlockNumber, AccountId, Index, Balance, Hash, };
use fc_api::Backend;
use fc_rpc_core::types::{FilterPool};
use fc_rpc::{EthBlockDataCacheTask};
use fp_rpc::EthereumRuntimeRPCApi;
use jsonrpsee::RpcModule;
use pallet_contracts::ContractsApi;
use polkadot_sdk::polkadot_service::FullClient;
use sc_client_api::StorageProvider;
use sc_network_sync::SyncingService;
use sc_consensus_babe::{BabeConfiguration, Epoch};
use sc_consensus_epochs::SharedEpochChanges;
use sc_consensus_grandpa::{FinalityProofProvider, SharedVoterState, SharedAuthoritySet, GrandpaJustificationStream};
use sc_service::TransactionPool;
use sc_transaction_pool::ChainApi;
use sp_core::H256;
use sp_inherents::CreateInherentDataProviders;
use sp_keystore::KeystorePtr;
pub use sc_rpc::SubscriptionTaskExecutor;
pub use sc_rpc_api::DenyUnsafe;
use sp_api::ProvideRuntimeApi;
use sp_block_builder::BlockBuilder;
use sp_blockchain::{Error as BlockChainError, HeaderMetadata, HeaderBackend};
use sp_consensus::SelectChain;
use sp_consensus_babe::BabeApi;
use sc_network::service::traits::NetworkService;
use jsonrpc_pubsub::manager::SubscriptionManager;
use sc_consensus_manual_seal::rpc::ManualSeal;
use sp_runtime::traits::Block as BlockT;
use sc_consensus_manual_seal::rpc::ManualSealApiServer;

use crate::{rpc::eth::create_eth, service::FullFrontierBackend};

use self::eth::EthDeps;

pub mod eth;

/// Extra dependencies for BABE. 
pub struct BabeDeps {
  /// The keystore that manages the keys of the node.
  pub keystore: KeystorePtr,
	/// A handle to the BABE worker for issuing requests.
	pub babe_worker_handle: sc_consensus_babe::BabeWorkerHandle<Block>,
}

/// Extra dependencies for GRANDPA
pub struct GrandpaDeps<B> {
  /// Voting round info.
  pub shared_voter_state: SharedVoterState,
  /// Authority set info.
  pub shared_authority_set: SharedAuthoritySet<Hash, BlockNumber>,
  /// Receives notifications about justification events from Grandpa.
  pub justification_stream: GrandpaJustificationStream<Block>,
  /// Subscription manager to keep track of pubsub subscribers.
  pub subscription_executor: SubscriptionTaskExecutor,
  /// Finality proof provider.
  pub finality_provider: Arc<FinalityProofProvider<B, Block>>,
}

/// Full client dependencies.
pub struct FullDeps<C, P, SC, B, CT, CIDP> {
  /// The client instance to use.
  pub client: Arc<C>,
  /// Transaction pool instance.
  pub pool: Arc<P>,
  /// The SelectChain Strategy
  pub select_chain: SC,
  /// A copy of the chain spec.
	pub chain_spec: Box<dyn sc_chain_spec::ChainSpec>,
  /// Whether to deny unsafe calls
  pub deny_unsafe: DenyUnsafe,
  /// BABE specific dependencies.
  pub babe: Option<BabeDeps>,
  /// GRANDPA specific dependencies.
  pub grandpa: GrandpaDeps<B>,
	/// The backend used by the node.
	pub backend: Arc<B>,
  /// Maximum number of logs in a query.
	pub max_past_logs: u32,
  /// The Node authority flag
  pub is_authority: bool,
  /// Network service
  pub network: Arc<dyn NetworkService>,
  /// Manual seal command sink
  pub command_sink: Option<futures::channel::mpsc::Sender<sc_consensus_manual_seal::rpc::EngineCommand<Hash>>>,
  /// Eth deps
  pub eth: EthDeps<CT, CIDP>, 
}

pub struct DefaultEthConfig<C, BE>(std::marker::PhantomData<(C, BE)>);

impl<C, BE> fc_rpc::EthConfig<Block, C> for DefaultEthConfig<C, BE>
where
	C: StorageProvider<Block, BE> + Sync + Send + 'static,
	BE: Backend<Block> + sc_client_api::Backend<Block> + 'static,
{
	type EstimateGasAdapter = ();
	type RuntimeStorageOverride =
		fc_rpc::frontier_backend_client::SystemAccountId20StorageOverride<Block, C, BE>;
}

/// Instantiate all Full RPC extensions.
pub fn create_full<P, SC, CIDP, CT>(
  deps: FullDeps<FullClient, P, SC, FullFrontierBackend, CT, CIDP>,
  subscription_task_executor: SubscriptionTaskExecutor,
  pubsub_notification_sinks: Arc<
    fc_mapping_sync::EthereumBlockNotificationSinks<
        fc_mapping_sync::EthereumBlockNotification<Block>,
    >
  >,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
  P: TransactionPool<Block = Block> + 'static,
  SC: SelectChain<Block> +'static, 
  CIDP: CreateInherentDataProviders<Block, ()> + Send + 'static,
  CT: fp_rpc::ConvertTransaction<<Block as BlockT>::Extrinsic> + Send + Sync + 'static,
{
	use fc_rpc::{Debug, DebugApiServer, Eth, EthApiServer, EthDevSigner,
		EthFilter, EthFilterApiServer, EthPubSub, EthPubSubApiServer, EthSigner, Net, NetApiServer,
		Web3,
	};
	use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};
	use sc_consensus_babe_rpc::{Babe, BabeApiServer};
	use sc_consensus_grandpa_rpc::{Grandpa, GrandpaApiServer};
	use sc_rpc::dev::{Dev, DevApiServer};
	use sc_sync_state_rpc::{SyncState, SyncStateApiServer};
	use substrate_frame_rpc_system::{System, SystemApiServer};

	let mut io = RpcModule::new(());

  let FullDeps {
    client,
    pool,
    select_chain,
    chain_spec,
    deny_unsafe,
    babe,
    grandpa,
    network,
    backend, 
    max_past_logs,
    is_authority,
    command_sink,
    eth,
  } = deps;

  let GrandpaDeps {
    shared_voter_state,
    shared_authority_set,
    justification_stream,
    subscription_executor,
    finality_provider,
  } = grandpa; 

  io.merge(System::new(client.clone(), pool.clone(), deny_unsafe).into_rpc())?;
	io.merge(TransactionPayment::new(client.clone()).into_rpc())?;

  // io.merge(ContractsApi::to_delegate(Contracts::new(client.clone())));
  if let Some(BabeDeps { babe_worker_handle, keystore }) = babe {
    io.merge(
      Babe::new(client.clone(), babe_worker_handle.clone(), keystore, select_chain, deny_unsafe)
        .into_rpc(),
    )?;

    io.merge(
      SyncState::new(chain_spec, client.clone(), shared_authority_set, babe_worker_handle)?
        .into_rpc(),
    )?;
  }

	io.merge(
		Grandpa::new(
			subscription_executor,
			shared_authority_set.clone(),
			shared_voter_state,
			justification_stream,
			finality_provider,
		)
		.into_rpc(),
	)?;
 
  // The final RPC extension receives commands for the manual seal consensus engine.
  if let Some(command_sink) = command_sink {
    io.merge(
      // We provide the rpc handler with the sending end of the channel to allow the rpc
      // send EngineCommands to the background block authorship task.
      ManualSeal::new(command_sink).into_rpc(),
    )?;
  }

  let io = create_eth::<_, _, DefaultEthConfig<FullClient, FullFrontierBackend>>(
      io,
      eth,
      subscription_task_executor,
      pubsub_notification_sinks,
  )?;

  Ok(io)
}
