//! A collection of node-specific RPC methods.
//! Substrate provides the `sc-rpc` crate, which defines the core RPC layer
//! used by Substrate nodes. This file extends those RPC definitions with
//! capabilities that are specific to this project's runtime configuration.

#![warn(missing_docs)]
use std::sync::Arc;

use clover_primitives::{AccountId, Balance, Block, BlockNumber, Hash, Index};
use fc_rpc::{
    Eth, EthFilter, OverrideHandle, RuntimeApiStorageOverride, SchemaV1Override, StorageOverride,
};
use fc_rpc_core::types::FilterPool;
use jsonrpc_pubsub::manager::SubscriptionManager;
use jsonrpsee::RpcModule;
use pallet_ethereum::EthereumStorageSchema;
use sc_consensus_babe::{BabeConfiguration, Epoch};
use sc_consensus_babe_rpc::BabeApiServer;
use sc_consensus_epochs::SharedEpochChanges;
use sc_consensus_grandpa::{
    FinalityProofProvider, GrandpaJustificationStream, SharedAuthoritySet, SharedVoterState,
};
use sc_consensus_grandpa_rpc::GrandpaApiServer;
use sc_consensus_manual_seal::rpc::{ManualSeal, ManualSealApi};
use sc_network::NetworkService;
use sc_rpc::system::SyncState;
pub use sc_rpc::SubscriptionTaskExecutor;
pub use sc_rpc_api::DenyUnsafe;
use sc_service::TransactionPool;
use sp_api::ProvideRuntimeApi;
use sp_block_builder::BlockBuilder;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};
use sp_consensus::SelectChain;
use sp_consensus_babe::BabeApi;
use sp_inherents::CreateInherentDataProviders;
use sp_keystore::SyncCryptoStorePtr;
use sp_transaction_pool::TransactionPool;
use std::collections::BTreeMap;

/// Light client extra dependencies.
pub struct LightDeps<C, F, P> {
    /// The client instance to use.
    pub client: Arc<C>,
    /// Transaction pool instance.
    pub pool: Arc<P>,
    /// Remote access to the blockchain (async).
    pub remote_blockchain: Arc<dyn sc_client_api::light::RemoteBlockchain<Block>>,
    /// Fetcher instance.
    pub fetcher: Arc<F>,
}

/// Extra dependencies for BABE.
pub struct BabeDeps {
    /// BABE protocol config.
    pub babe_config: Config,
    /// BABE pending epoch changes.
    pub shared_epoch_changes: SharedEpochChanges<Block, Epoch>,
    /// The keystore that manages the keys of the node.
    pub keystore: SyncCryptoStorePtr,
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
pub struct FullDeps<C, P, SC, B> {
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
    pub babe: BabeDeps,
    /// GRANDPA specific dependencies.
    pub grandpa: GrandpaDeps<B>,
    /// EthFilterApi pool.
    pub filter_pool: Option<FilterPool>,
    /// Backend.
    pub backend: Arc<fc_db::Backend<Block>>,
    /// Maximum number of logs in a query.
    pub max_past_logs: u32,
    /// The Node authority flag
    pub is_authority: bool,
    /// Network service
    pub network: Arc<NetworkService<Block, Hash>>,
    /// Manual seal command sink
    pub command_sink:
        Option<futures::channel::mpsc::Sender<sc_consensus_manual_seal::rpc::EngineCommand<Hash>>>,
}

/// A IO handler that uses all Full RPC extensions.
pub type IoHandler = jsonrpc_core::IoHandler<sc_rpc::Metadata>;

/// Instantiate all Full RPC extensions.
pub fn create_full<C, P, SC, B, CIDP>(
    deps: FullDeps<C, P, SC, B>,
    subscription_task_executor: SubscriptionTaskExecutor,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
    C: ProvideRuntimeApi<Block>
        + sc_client_api::backend::StorageProvider<Block, B>
        + sc_client_api::AuxStore,
    C: sc_client_api::client::BlockchainEvents<Block>,
    C: HeaderBackend<Block> + HeaderMetadata<Block, Error = BlockChainError> + 'static,
    C: Send + Sync + 'static,
    C::Api: substrate_frame_rpc_system::AccountNonceApi<Block, AccountId, Index>,
    C::Api: pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>,
    C::Api: fc_rpc::EthereumRpcApi<Block>,
    C::Api: BabeApi<Block>,
    C::Api: BlockBuilder<Block>,
    CIDP: CreateInherentDataProviders<B, ()> + Send + 'static,
    P: TransactionPool<Block = Block> + 'static,
    SC: SelectChain<Block> + 'static,
    B: sc_client_api::Backend<Block> + Send + Sync + 'static,
    B::State: sc_client_api::StateBackend<sp_runtime::HashFor<Block>>,
{
    use fc_rpc::{
        EthApi, EthApiServer, EthDevSigner, EthFilterApi, EthFilterApiServer, EthPubSub,
        EthPubSubApi, EthPubSubApiServer, EthSigner, HexEncodedIdProvider, Net, NetApi,
        NetApiServer, Web3, Web3Api, Web3ApiServer,
    };
    use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};
    use sc_consensus_babe_rpc::{Babe, BabeApiServer};
    use sc_consensus_grandpa_rpc::{Grandpa, GrandpaApiServer};
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
        filter_pool,
        backend,
        max_past_logs,
        is_authority,
        command_sink,
    } = deps;

    let BabeDeps {
        babe_config,
        shared_epoch_changes,
        keystore,
    } = babe;

    let GrandpaDeps {
        shared_voter_state,
        shared_authority_set,
        justification_stream,
        subscription_executor,
        finality_provider,
    } = grandpa;

    io.merge(System::new(client.clone(), pool, deny_unsafe).into_rpc())?;

    io.merge(TransactionPayment::new(client.clone()).into_rpc())?;

    io.merge(
        Babe::new(
            client.clone(),
            babe_worker_handle.clone(),
            keystore,
            select_chain,
            deny_unsafe,
        )
        .into_rpc(),
    )?;
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

    io.merge(
        SyncState::new(
            chain_spec,
            client.clone(),
            shared_authority_set,
            babe_worker_handle,
        )?
        .into_rpc(),
    )?;

    let mut signers = Vec::new();
    signers.push(Box::new(EthDevSigner::new()) as Box<dyn EthSigner>);

    let mut overrides_map = BTreeMap::new();
    overrides_map.insert(
        EthreumStorageSchema::V1,
        Box::new(SchemaV1Override::new(client.clone()))
            as Box<dyn StorageOverride<_> + Send + Sync>,
    );

    let overrides = Arc::new(OverrideHandle {
        schemas: overrides_map,
        fallback: Box::new(RuntimeApiStorageOverride::new(client.clone())),
    });

    io.merge(Eth::<B, C, P, CT, BE, A, CIDP, EC>::new(
        client.clone(),
        pool.clone(),
        clover_runtime::TransactionConverter,
        network.clone(),
        signers,
        overrides.clone(),
        backend,
        is_authority,
        max_past_logs,
    ));

    if let Some(filter_pool) = filter_pool {
        io.merge(EthFilter::new(
            client.clone(),
            filter_pool.clone(),
            500 as usize, // max stored filters
            overrides.clone(),
            max_past_logs,
        ));
    }

    io.merge(Net::new(client.clone(), network.clone(), true));

    io.merge(Web3::new(client.clone()));

    io.merge(EthPubSub::new(
        pool.clone(),
        client.clone(),
        network.clone(),
        SubscriptionManager::<HexEncodedIdProvider>::with_id_provider(
            HexEncodedIdProvider::default(),
            Arc::new(subscription_task_executor),
        ),
        overrides,
    ));

    // The final RPC extension receives commands for the manual seal consensus engine.
    if let Some(command_sink) = command_sink {
        io.merge(
            // We provide the rpc handler with the sending end of the channel to allow the rpc
            // send EngineCommands to the background block authorship task.
            ManualSeal::new(command_sink),
        );
    }

    io
}

/// Instantiate all Light RPC extensions.
pub fn create_light<C, P, M, F>(deps: LightDeps<C, F, P>) -> jsonrpc_core::IoHandler<M>
where
    C: sp_blockchain::HeaderBackend<Block>,
    C: Send + Sync + 'static,
    F: sc_client_api::light::Fetcher<Block> + 'static,
    P: TransactionPool + 'static,
    M: jsonrpc_core::Metadata + Default,
{
    use substrate_frame_rpc_system::{LightSystem, SystemApi};

    let LightDeps {
        client,
        pool,
        remote_blockchain,
        fetcher,
    } = deps;
    let mut io = jsonrpc_core::IoHandler::default();
    io.extend_with(SystemApi::<Hash, AccountId, Index>::to_delegate(
        LightSystem::new(client, remote_blockchain, fetcher, pool),
    ));

    io
}
