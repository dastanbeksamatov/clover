// //! A collection of node-specific RPC methods.
// //! Substrate provides the `sc-rpc` crate, which defines the core RPC layer
// //! used by Substrate nodes. This file extends those RPC definitions with
// //! capabilities that are specific to this project's runtime configuration.

// #![warn(missing_docs)]
// use std::sync::Arc;

// use clover_primitives::{AccountId, Balance, Hash, Index};
// use jsonrpc_pubsub::manager::SubscriptionManager;
// use jsonrpsee::RpcModule;
// use sc_client_api::backend::Backend;
// use sc_client_api::{AuxStore, BlockchainEvents, StorageProvider, UsageProvider};
// use sc_consensus_grandpa::{
//     BlockNumberOps, FinalityProofProvider, GrandpaJustificationStream, SharedAuthoritySet,
//     SharedVoterState,
// };
// use sc_consensus_manual_seal::rpc::{ManualSeal, ManualSealApiServer};
// use sc_network::service::traits::NetworkService;
// pub use sc_rpc::SubscriptionTaskExecutor;
// pub use sc_rpc_api::DenyUnsafe;
// use sc_transaction_pool::ChainApi;
// use serde_json::Number;
// use sp_api::{CallApiAt, ProvideRuntimeApi};
// use sp_block_builder::BlockBuilder;
// use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};
// use sp_consensus::SelectChain;
// use sp_consensus_babe::BabeApi;
// use sp_inherents::CreateInherentDataProviders;
// use sp_keystore::KeystorePtr;
// use sp_runtime::traits::{Block as BlockT, NumberFor};

// use crate::rpc::eth::create_eth;
// use crate::service::{FullBackend, FullFrontierBackend};

// use self::eth::EthDeps;

// /// ETH RPC module
// pub mod eth;

// /// Extra dependencies for BABE.
// pub struct BabeDeps<B: BlockT> {
//     /// The keystore that manages the keys of the node.
//     pub keystore: KeystorePtr,
//     /// A handle to the BABE worker for issuing requests.
//     pub babe_worker_handle: sc_consensus_babe::BabeWorkerHandle<B>,
// }

// /// Extra dependencies for GRANDPA
// pub struct GrandpaDeps<B: BlockT, BE> {
//     /// Voting round info.
//     pub shared_voter_state: SharedVoterState,
//     /// Authority set info.
//     pub shared_authority_set: SharedAuthoritySet<B::Hash, NumberFor<B>>,
//     /// Receives notifications about justification events from Grandpa.
//     pub justification_stream: GrandpaJustificationStream<B>,
//     /// Subscription manager to keep track of pubsub subscribers.
//     pub subscription_executor: SubscriptionTaskExecutor,
//     /// Finality proof provider.
//     pub finality_provider: Arc<FinalityProofProvider<BE, B>>,
// }

// /// Full client dependencies.
// pub struct FullDeps<B: BlockT, C, P, A: ChainApi, SC, BE, CT, CIDP> {
//     /// The client instance to use.
//     pub client: Arc<C>,
//     /// Transaction pool instance.
//     pub pool: Arc<P>,
//     /// The SelectChain Strategy
//     pub select_chain: SC,
//     /// A copy of the chain spec.
//     pub chain_spec: Box<dyn sc_chain_spec::ChainSpec>,
//     /// Whether to deny unsafe calls
//     pub deny_unsafe: DenyUnsafe,
//     /// BABE specific dependencies.
//     pub babe: Option<BabeDeps<B>>,
//     /// GRANDPA specific dependencies.
//     pub grandpa: GrandpaDeps<B, BE>,
//     /// The backend used by the node.
//     pub backend: Arc<BE>,
//     /// Maximum number of logs in a query.
//     pub max_past_logs: u32,
//     /// The Node authority flag
//     pub is_authority: bool,
//     /// Network service
//     pub network: Arc<dyn NetworkService>,
//     /// Manual seal command sink
//     pub command_sink:
//         Option<futures::channel::mpsc::Sender<sc_consensus_manual_seal::rpc::EngineCommand<Hash>>>,
//     /// Eth deps
//     pub eth: EthDeps<B, C, P, A, CT, CIDP>,
// }

// /// Default ETH config
// pub struct DefaultEthConfig<C, BE>(std::marker::PhantomData<(C, BE)>);

// impl<B, C, BE> fc_rpc::EthConfig<B, C> for DefaultEthConfig<C, BE>
// where
//     B: BlockT,
//     C: StorageProvider<B, BE> + Sync + Send + 'static,
//     BE: Backend<B> + 'static,
// {
//     type EstimateGasAdapter = ();
//     type RuntimeStorageOverride =
//         fc_rpc::frontier_backend_client::SystemAccountId20StorageOverride<B, C, BE>;
// }

// /// Instantiate all Full RPC extensions.
// pub fn create_full<B, C, P, SC, BE, A, CT, CIDP>(
//     deps: FullDeps<B, C, P, A, SC, BE, CT, CIDP>,
//     subscription_task_executor: SubscriptionTaskExecutor,
//     pubsub_notification_sinks: Arc<
//         fc_mapping_sync::EthereumBlockNotificationSinks<
//             fc_mapping_sync::EthereumBlockNotification<B>,
//         >,
//     >,
// ) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
// where
//     B: BlockT,
//     NumberFor<B>: BlockNumberOps,
//     C: CallApiAt<B> + ProvideRuntimeApi<B>,
//     C::Api: sp_block_builder::BlockBuilder<B>,
//     C::Api: sp_consensus_babe::BabeApi<B>,
//     C::Api: substrate_frame_rpc_system::AccountNonceApi<B, AccountId, Index>,
//     C::Api: pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<B, Balance>,
//     C::Api: fp_rpc::ConvertTransactionRuntimeApi<B>,
//     C::Api: fp_rpc::EthereumRuntimeRPCApi<B>,
//     C::Api: BabeApi<B>,
//     C: HeaderBackend<B> + HeaderMetadata<B, Error = BlockChainError> + 'static,
//     C: BlockchainEvents<B> + AuxStore + UsageProvider<B> + StorageProvider<B, BE>,
//     SC: SelectChain<B> + 'static,
//     BE: Backend<B> + Send + Sync + 'static,
//     BE::State: sc_client_api::backend::StateBackend<sp_runtime::traits::HashingFor<B>>,
//     P: sc_service::TransactionPool<Block = B> + 'static,
//     A: ChainApi<Block = B> + 'static,
//     CIDP: CreateInherentDataProviders<B, ()> + Send + 'static,
//     CT: fp_rpc::ConvertTransaction<<B as BlockT>::Extrinsic> + Send + Sync + 'static,
// {
//     use fc_rpc::{EthDevSigner, EthFilter, EthPubSub, EthPubSubApiServer, EthSigner, Net, Web3};
//     use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};
//     use sc_consensus_babe_rpc::{Babe, BabeApiServer};
//     use sc_consensus_grandpa_rpc::{Grandpa, GrandpaApiServer};
//     use sc_sync_state_rpc::{SyncState, SyncStateApiServer};
//     use substrate_frame_rpc_system::{System, SystemApiServer};

//     let mut io = RpcModule::new(());

//     let FullDeps {
//         client,
//         pool,
//         select_chain,
//         chain_spec,
//         deny_unsafe,
//         babe,
//         grandpa,
//         network,
//         backend,
//         max_past_logs,
//         is_authority,
//         command_sink,
//         eth,
//     } = deps;

//     let GrandpaDeps {
//         shared_voter_state,
//         shared_authority_set,
//         justification_stream,
//         subscription_executor,
//         finality_provider,
//     } = grandpa;

//     io.merge(System::new(client.clone(), pool.clone(), deny_unsafe).into_rpc())?;
//     io.merge(TransactionPayment::new(client.clone()).into_rpc())?;

//     // io.merge(ContractsApi::to_delegate(Contracts::new(client.clone())));
//     if let Some(BabeDeps {
//         babe_worker_handle,
//         keystore,
//     }) = babe
//     {
//         io.merge(
//             Babe::new(
//                 client.clone(),
//                 babe_worker_handle.clone(),
//                 keystore,
//                 select_chain,
//                 deny_unsafe,
//             )
//             .into_rpc(),
//         )?;

//         io.merge(
//             SyncState::new(
//                 chain_spec,
//                 client.clone(),
//                 shared_authority_set.clone(),
//                 babe_worker_handle,
//             )?
//             .into_rpc(),
//         )?;
//     }

//     io.merge(
//         Grandpa::new(
//             subscription_executor,
//             shared_authority_set.clone(),
//             shared_voter_state,
//             justification_stream,
//             finality_provider,
//         )
//         .into_rpc(),
//     )?;

//     // The final RPC extension receives commands for the manual seal consensus engine.
//     if let Some(command_sink) = command_sink {
//         io.merge(
//             // We provide the rpc handler with the sending end of the channel to allow the rpc
//             // send EngineCommands to the background block authorship task.
//             ManualSeal::new(command_sink).into_rpc(),
//         )?;
//     }

//     let io = create_eth::<_, _, _, _, _, _, _, DefaultEthConfig<C, BE>>(
//         io,
//         eth,
//         subscription_task_executor,
//         pubsub_notification_sinks,
//     )?;

//     Ok(io)
// }

// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! A collection of node-specific RPC methods.
//!
//! Since `substrate` core functionality makes no assumptions
//! about the modules used inside the runtime, so do
//! RPC methods defined in `sc-rpc` crate.
//! It means that `client/rpc` can't have any methods that
//! need some strong assumptions about the particular runtime.
//!
//! The RPCs available in this crate however can make some assumptions
//! about how the runtime is constructed and what FRAME pallets
//! are part of it. Therefore all node-runtime-specific RPCs can
//! be placed here or imported from corresponding FRAME RPC definitions.

#![warn(missing_docs)]
#![warn(unused_crate_dependencies)]

use std::sync::Arc;

use clover_primitives::{AccountId, Balance, Block, BlockNumber, Hash, Index as Nonce};
use jsonrpsee::RpcModule;
use sc_client_api::AuxStore;
use sc_consensus_babe::BabeWorkerHandle;
use sc_consensus_grandpa::{
    FinalityProofProvider, GrandpaJustificationStream, SharedAuthoritySet, SharedVoterState,
};
pub use sc_rpc::SubscriptionTaskExecutor;
pub use sc_rpc_api::DenyUnsafe;
use sc_transaction_pool_api::TransactionPool;
use sp_api::ProvideRuntimeApi;
use sp_application_crypto::RuntimeAppPublic;
use sp_block_builder::BlockBuilder;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};
use sp_consensus::SelectChain;
use sp_consensus_babe::BabeApi;
use sp_keystore::KeystorePtr;

/// Extra dependencies for BABE.
pub struct BabeDeps {
    /// A handle to the BABE worker for issuing requests.
    pub babe_worker_handle: BabeWorkerHandle<Block>,
    /// The keystore that manages the keys of the node.
    pub keystore: KeystorePtr,
}

/// Extra dependencies for GRANDPA
pub struct GrandpaDeps<B> {
    /// Voting round info.
    pub shared_voter_state: SharedVoterState,
    /// Authority set info.
    pub shared_authority_set: SharedAuthoritySet<Hash, BlockNumber>,
    /// Receives notifications about justification events from Grandpa.
    pub justification_stream: GrandpaJustificationStream<Block>,
    /// Executor to drive the subscription manager in the Grandpa RPC handler.
    pub subscription_executor: SubscriptionTaskExecutor,
    /// Finality proof provider.
    pub finality_provider: Arc<FinalityProofProvider<B, Block>>,
}

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
    /// The backend used by the node.
    pub backend: Arc<B>,
    /// Mixnet API.
    pub mixnet_api: Option<sc_mixnet::Api>,
}

/// Instantiate all Full RPC extensions.
pub fn create_full<C, P, SC, B>(
    FullDeps {
        client,
        pool,
        select_chain,
        chain_spec,
        deny_unsafe,
        babe,
        grandpa,
        backend,
        mixnet_api,
    }: FullDeps<C, P, SC, B>,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
    C: ProvideRuntimeApi<Block>
        + sc_client_api::BlockBackend<Block>
        + HeaderBackend<Block>
        + AuxStore
        + HeaderMetadata<Block, Error = BlockChainError>
        + Sync
        + Send
        + 'static,
    C::Api: substrate_frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>,
    C::Api: pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>,
    C::Api: BabeApi<Block>,
    C::Api: BlockBuilder<Block>,
    P: TransactionPool + 'static,
    SC: SelectChain<Block> + 'static,
    B: sc_client_api::Backend<Block> + Send + Sync + 'static,
    B::State: sc_client_api::backend::StateBackend<sp_runtime::traits::HashingFor<Block>>,
{
    use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};
    use sc_consensus_babe_rpc::{Babe, BabeApiServer};
    use sc_consensus_grandpa_rpc::{Grandpa, GrandpaApiServer};
    use sc_rpc::dev::{Dev, DevApiServer};
    use sc_rpc::mixnet::MixnetApiServer;
    use sc_rpc::statement::StatementApiServer;
    use sc_sync_state_rpc::{SyncState, SyncStateApiServer};
    use substrate_frame_rpc_system::{System, SystemApiServer};

    let mut io = RpcModule::new(());

    let BabeDeps {
        keystore,
        babe_worker_handle,
    } = babe;
    let GrandpaDeps {
        shared_voter_state,
        shared_authority_set,
        justification_stream,
        subscription_executor,
        finality_provider,
    } = grandpa;

    let chain_name = chain_spec.name().to_string();
    let genesis_hash = client
        .block_hash(0)
        .ok()
        .flatten()
        .expect("Genesis block exists; qed");
    let properties = chain_spec.properties();

    io.merge(System::new(client.clone(), pool, deny_unsafe).into_rpc())?;
    // Making synchronous calls in light client freezes the browser currently,
    // more context: https://github.com/paritytech/substrate/pull/3480
    // These RPCs should use an asynchronous caller instead.
    // io.merge(
    //     Mmr::new(
    //         client.clone(),
    //         backend
    //             .offchain_storage()
    //             .ok_or_else(|| "Backend doesn't provide an offchain storage")?,
    //     )
    //     .into_rpc(),
    // )?;
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

    // io.merge(StateMigration::new(client.clone(), backend, deny_unsafe).into_rpc())?;
    io.merge(Dev::new(client, deny_unsafe).into_rpc())?;
    // let statement_store =
    //     sc_rpc::statement::StatementStore::new(statement_store, deny_unsafe).into_rpc();
    // io.merge(statement_store)?;

    if let Some(mixnet_api) = mixnet_api {
        let mixnet = sc_rpc::mixnet::Mixnet::new(mixnet_api).into_rpc();
        io.merge(mixnet)?;
    }

    Ok(io)
}
