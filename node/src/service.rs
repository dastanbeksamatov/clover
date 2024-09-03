//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

use std::{collections::{BTreeMap, HashMap}, path::Path, sync::{Arc, Mutex}, time::Duration};
use polkadot_sdk::sc_transaction_pool_api::OffchainTransactionPoolFactory;
use polkadot_sdk::sc_offchain;
use sc_client_api::{ExecutorProvider, BlockchainEvents};
use fc_rpc_core::types::FilterPool;
use fc_rpc::EthTask;
use clover_runtime::{self, opaque::Block, RuntimeApi, TransactionConverter};
use sc_consensus::BasicQueue;
use sc_consensus_babe::{BabeWorkerHandle, SlotProportion};
use sc_executor::WasmExecutor;
use sc_network::{service::traits::NetworkService, Event, NetworkBackend};
use sc_network_sync::SyncingService;
use sc_rpc::{mixnet, statement::StatementStore};
use sc_service::{error::Error as ServiceError, BasePath, Configuration, PartialComponents, RpcHandlers, TaskManager};
use sp_core::H256;
use sp_inherents::InherentDataProvider;
use sp_runtime::traits::Block as BlockT;
use sc_cli::SubstrateCli;
use sc_telemetry::{Telemetry, TelemetryConnectionNotifier, TelemetryWorker};
use fc_mapping_sync::kv::MappingSyncWorker;
use futures::channel::mpsc::Receiver;
use futures::StreamExt;
use sc_consensus_manual_seal::{EngineCommand, ManualSealParams};
use clover_primitives::Hash;
pub use crate::eth::{db_config_dir, EthConfiguration};
use crate::
	eth::{
		new_frontier_partial, spawn_frontier_tasks, BackendType, EthCompatRuntimeApiCollection,
		FrontierBackend, FrontierBlockImport, FrontierPartialComponents, StorageOverride,
		StorageOverrideHandler,
	};

use crate::cli::Cli;
/// Only enable the benchmarking host functions when we actually want to benchmark.
#[cfg(feature = "runtime-benchmarks")]
pub type HostFunctions = (
	sp_io::SubstrateHostFunctions,
	frame_benchmarking::benchmarking::HostFunctions,
);
/// Otherwise we use empty host functions for ext host functions.
#[cfg(not(feature = "runtime-benchmarks"))]
pub type HostFunctions = sp_io::SubstrateHostFunctions;

/// Full backend.
pub type FullBackend = sc_service::TFullBackend<Block>;
/// A specialized `WasmExecutor` intended to use across substrate node. It provides all required
/// HostFunctions.
pub type RuntimeExecutor = sc_executor::WasmExecutor<HostFunctions>;

/// The full client type definition.
pub type FullClient = sc_service::TFullClient<Block, RuntimeApi, RuntimeExecutor>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;
type FullGrandpaBlockImport =
  sc_consensus_grandpa::GrandpaBlockImport<FullBackend, Block, FullClient, FullSelectChain>;

/// The transaction pool type definition.
pub type TransactionPool = sc_transaction_pool::FullPool<Block, FullClient>;

/// The minimum period of blocks on which justifications will be
/// imported and generated.
const GRANDPA_JUSTIFICATION_PERIOD: u32 = 512;

pub fn new_partial<B>(
  config: &Configuration,
  cli: &Cli,
	eth_config: &EthConfiguration,
  mixnet_config: Option<&sc_mixnet::Config>,
) -> Result<sc_service::PartialComponents<
  FullClient,
  FullBackend,
  FullSelectChain,
  sc_consensus::DefaultImportQueue<Block>,
  sc_transaction_pool::FullPool<Block, FullClient>,
  (
    (
      sc_consensus_babe::BabeBlockImport<Block, FullClient, FullGrandpaBlockImport>,
      sc_finality_grandpa::LinkHalf<Block, FullClient, FullSelectChain>,
      sc_consensus_babe::BabeLink<Block>,
    ),
    (
      Option<FilterPool>,
      Arc<fc_db::Backend<Block, FullClient>>,
      FrontierBlockImport<
        Block,
        FullGrandpaBlockImport,
        FullClient,
      >,
			Arc<dyn StorageOverride<B>>,
			Option<Telemetry>,
			Option<sc_mixnet::ApiBackend>,
			Arc<StatementStore>,
      Option<BabeWorkerHandle<Block>>
    ),
  )
>, ServiceError> 
where
B: BlockT<Hash = H256>, 
{
  let telemetry = config
    .telemetry_endpoints
    .clone()
    .filter(|x| !x.is_empty())
    .map(|endpoints| -> Result<_, sc_telemetry::Error> {
      let worker = TelemetryWorker::new(16)?;
      let telemetry = worker.handle().new_telemetry(endpoints);
      Ok((worker, telemetry))
    })
    .transpose()?;

	let executor = sc_service::new_wasm_executor(&config);

  let (client, backend, keystore_container, task_manager) =
    sc_service::new_full_parts::<Block, RuntimeApi, _>(&config,
      telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
			executor,
    )?;
  let client = Arc::new(client);

	let telemetry = telemetry.map(|(worker, telemetry)| {
		task_manager.spawn_handle().spawn("telemetry", None, worker.run());
		telemetry
	});
  
  let select_chain = sc_consensus::LongestChain::new(backend.clone());

  let transaction_pool = sc_transaction_pool::BasicPool::new_full(
    config.transaction_pool.clone(),
    config.role.is_authority().into(),
    config.prometheus_registry(),
    task_manager.spawn_handle(),
    client.clone(),
  );

  let filter_pool: Option<FilterPool>
      = Some(Arc::new(Mutex::new(BTreeMap::new())));

	let (grandpa_block_import, grandpa_link) = sc_consensus_grandpa::block_import(
		client.clone(),
		GRANDPA_JUSTIFICATION_PERIOD,
		&(client.clone() as Arc<_>),
		select_chain.clone(),
		telemetry.as_ref().map(|x| x.handle()),
	)?;

  let justification_import = grandpa_block_import.clone();

  let storage_override = Arc::new(StorageOverrideHandler::<B, _, _>::new(client.clone()));
  let frontier_backend = match eth_config.frontier_backend_type {
	  BackendType::KeyValue => FrontierBackend::KeyValue(Arc::new(fc_db::kv::Backend::open(
			Arc::clone(&client),
			&config.database,
			&db_config_dir(config),
		)?)),
		BackendType::Sql => {
			let db_path = db_config_dir(config).join("sql");
			std::fs::create_dir_all(&db_path).expect("failed creating sql db directory");
			let backend = futures::executor::block_on(fc_db::sql::Backend::new(
				fc_db::sql::BackendConfig::Sqlite(fc_db::sql::SqliteBackendConfig {
					path: Path::new("sqlite:///")
						.join(db_path)
						.join("frontier.db3")
						.to_str()
						.unwrap(),
					create_if_missing: true,
					thread_count: eth_config.frontier_sql_backend_thread_count,
					cache_size: eth_config.frontier_sql_backend_cache_size,
				}),
				eth_config.frontier_sql_backend_pool_size,
				std::num::NonZeroU32::new(eth_config.frontier_sql_backend_num_ops_timeout),
				storage_override.clone(),
			))
			.unwrap_or_else(|err| panic!("failed creating sql backend: {:?}", err));
			FrontierBackend::Sql(Arc::new(backend))
		}
	};
  
  let frontier_block_import = FrontierBlockImport::new(
      grandpa_block_import.clone(),
      client.clone(),
    );

  let (block_import, babe_link) = sc_consensus_babe::block_import(
    sc_consensus_babe::configuration(&*client)?,
    frontier_block_import.clone(),
    client.clone(),
  )?;

	let slot_duration = babe_link.config().slot_duration();

  let (import_queue, babe_worker_handle) = if cli.run.manual_seal {
    (sc_consensus_manual_seal::import_queue(
      Box::new(frontier_block_import.clone()),
      &task_manager.spawn_handle(),
      config.prometheus_registry(),
    ), None)
  } else {
    let (import_queue, babe_worker_handle) = sc_consensus_babe::import_queue(sc_consensus_babe::ImportQueueParams {
			link: babe_link.clone(),
			block_import: block_import.clone(),
			justification_import: Some(Box::new(justification_import)),
			client: client.clone(),
			select_chain: select_chain.clone(),
			create_inherent_data_providers: move |_, ()| async move {
				let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

				let slot =
				sp_consensus_babe::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
					*timestamp,
					slot_duration,
				);

				Ok((slot, timestamp))
			},
			spawner: &task_manager.spawn_essential_handle(),
			registry: config.prometheus_registry(),
			telemetry: telemetry.as_ref().map(|x| x.handle()),
			offchain_tx_pool_factory: OffchainTransactionPoolFactory::new(transaction_pool.clone()),
		})?;

    (
      import_queue,
      Some(babe_worker_handle)
    )
  };

  let import_setup = (block_import, grandpa_link, babe_link);
	let (_, mixnet_api_backend) = mixnet_config.map(sc_mixnet::Api::new).unzip();

  let statement_store = polkadot_sdk::sc_statement_store::Store::new_shared(
		&config.data_path,
		Default::default(),
		client.clone(),
		keystore_container.local_keystore(),
		config.prometheus_registry(),
		&task_manager.spawn_handle(),
	)
	.map_err(|e| ServiceError::Other(format!("Statement store error: {:?}", e)))?;

  Ok(sc_service::PartialComponents {
    client, backend, task_manager, keystore_container, select_chain, import_queue, transaction_pool,
    other: (import_setup, (filter_pool, frontier_backend, frontier_block_import, telemetry, mixnet_api_backend, statement_store, babe_worker_handle)),
  })
}


/// Result of [`new_full_base`].
pub struct NewFullBase {
	/// The task manager of the node.
	pub task_manager: TaskManager,
	/// The client instance of the node.
	pub client: Arc<FullClient>,
	/// The networking service of the node.
	pub network: Arc<dyn NetworkService>,
	/// The syncing service of the node.
	pub sync: Arc<SyncingService<Block>>,
	/// The transaction pool of the node.
	pub transaction_pool: Arc<TransactionPool>,
	/// The rpc handlers of the node.
	pub rpc_handlers: RpcHandlers,
}

/// Builds a new service for a full client.
pub async fn new_full_base<N: NetworkBackend<Block, <Block as BlockT>::Hash>>(
  mut config: Configuration,
  eth_config: &EthConfiguration,
  cli: &Cli,
	mixnet_config: Option<sc_mixnet::Config>,
  with_startup_data: impl FnOnce(
    &sc_consensus_babe::BabeBlockImport<Block, FullClient, FullGrandpaBlockImport>,
    &sc_consensus_babe::BabeLink<Block>,
  )
) -> Result<NewFullBase, ServiceError> {
  let is_offchain_indexing_enabled = config.offchain_worker.indexing_enabled;
	let role = config.role.clone();
	let force_authoring = config.force_authoring;

  let sc_service::PartialComponents {
    client, backend, mut task_manager, import_queue, keystore_container, select_chain, transaction_pool,
    other: (import_setup, (filter_pool,
    frontier_backend,frontier_block_import, storage_override, telemetry, mixnet_api_backend, statement_store, babe_worker_handle)),
  } = new_partial(&config, cli, eth_config, mixnet_config.cloned())?;

  let FrontierPartialComponents {
		filter_pool,
		fee_history_cache,
		fee_history_cache_limit,
	} = new_frontier_partial(&eth_config)?;

	let mut net_config =
  sc_network::config::FullNetworkConfiguration::<_, _, N>::new(&config.network);

  let genesis_hash = client.block_hash(0).ok().flatten().expect("Genesis block exists; qed");
	let peer_store_handle = net_config.peer_store_handle();

  let metrics = N::register_notification_metrics(
		config.prometheus_config.as_ref().map(|cfg| &cfg.registry),
	);
  let grandpa_protocol_name = sc_consensus_grandpa::protocol_standard_name(&genesis_hash, &config.chain_spec);


  config.network.extra_sets.push(sc_consensus_grandpa::grandpa_peers_set_config(
    grandpa_protocol_name.clone(),
    metrics.clone(),
    Arc::clone(&peer_store_handle),
)); 

  // #[cfg(feature = "cli")]
  // config.network.request_response_protocols.push(sc_finality_grandpa_warp_sync::request_response_config_for_chain(
  //   &config, task_manager.spawn_handle(), backend.clone(),
  // ));



	let (grandpa_protocol_config, grandpa_notification_service) =
  sc_consensus_grandpa::grandpa_peers_set_config::<_, N>(
			grandpa_protocol_name.clone(),
			metrics.clone(),
			Arc::clone(&peer_store_handle),
		);
	net_config.add_notification_protocol(grandpa_protocol_config);

  let warp_sync = Arc::new(sc_consensus_grandpa::warp_proof::NetworkProvider::new(
		backend.clone(),
		import_setup.1.shared_authority_set().clone(),
		Vec::default(),
	));

  let (network, system_rpc_tx, tx_handler_controller, network_starter, sync_service) =
    sc_service::build_network(sc_service::BuildNetworkParams {
      config: &config,
      client: client.clone(),
      net_config,
      warp_sync_params: Some(sc_service::WarpSyncParams::WithProvider(warp_sync)),
      transaction_pool: transaction_pool.clone(),
      spawn_handle: task_manager.spawn_handle(),
      import_queue,
      block_announce_validator_builder: None,
      block_relay: None,
      metrics,
    })?;

  let mixnet_protocol_name =
  sc_mixnet::protocol_name(genesis_hash.as_ref(), config.chain_spec.fork_id());
  let mixnet_notification_service = mixnet_config.as_ref().map(|mixnet_config| {
    let (config, notification_service) = sc_mixnet::peers_set_config::<_, N>(
      mixnet_protocol_name.clone(),
      mixnet_config,
      metrics.clone(),
      Arc::clone(&peer_store_handle),
    );
    net_config.add_notification_protocol(config);
    notification_service
  });

  if let Some(mixnet_config) = mixnet_config {
    let mixnet = sc_mixnet::run(
      mixnet_config,
      mixnet_api_backend.expect("Mixnet API backend created if mixnet enabled"),
      client.clone(),
      sync_service.clone(),
      network.clone(),
      mixnet_protocol_name,
      transaction_pool.clone(),
      Some(keystore_container.keystore()),
      mixnet_notification_service
        .expect("`NotificationService` exists since mixnet was enabled; qed"),
    );
    task_manager.spawn_handle().spawn("mixnet", None, mixnet);
  }

  if config.offchain_worker.enabled {
    task_manager.spawn_handle().spawn(
			"offchain-workers-runner",
			"offchain-work",
			sc_offchain::OffchainWorkers::new(sc_offchain::OffchainWorkerOptions {
				runtime_api_provider: client.clone(),
				keystore: Some(keystore_container.keystore()),
				offchain_db: backend.offchain_storage(),
				transaction_pool: Some(OffchainTransactionPoolFactory::new(
					transaction_pool.clone(),
				)),
				network_provider: Arc::new(network.clone()),
				is_validator: role.is_authority(),
				enable_http_requests: true,
				custom_extensions: move |_| {
					vec![Box::new(statement_store.clone().as_statement_store_ext()) as Box<_>]
				},
			})
			.run(client.clone(), task_manager.spawn_handle())
			.boxed(),
		);
  }

  let role = config.role.clone();
  let force_authoring = config.force_authoring;
  let backoff_authoring_blocks =
    Some(sc_consensus_slots::BackoffAuthoringOnFinalizedHeadLagging::default());
  let name = config.network.node_name.clone();
  let enable_grandpa = !config.disable_grandpa;
  let prometheus_registry = config.prometheus_registry().cloned();

  let network_clone = network.clone();

  let (_, grandpa_link, babe_link) = &import_setup;
  let keystore = keystore_container.keystore();
  let shared_authority_set = grandpa_link.shared_authority_set().clone();
  let justification_stream = grandpa_link.justification_stream();
  let shared_voter_state = sc_consensus_grandpa::SharedVoterState::empty();

	// Sinks for pubsub notifications.
	// Everytime a new subscription is created, a new mpsc channel is added to the sink pool.
	// The MappingSyncWorker sends through the channel on block import and the subscription emits a notification to the subscriber on receiving a message through this channel.
	// This way we avoid race conditions when using native substrate block import notification stream.
	let pubsub_notification_sinks: fc_mapping_sync::EthereumBlockNotificationSinks<
		fc_mapping_sync::EthereumBlockNotification<Block>,
	> = Default::default();
	let pubsub_notification_sinks = Arc::new(pubsub_notification_sinks);

  let (command_sink, commands_stream) = futures::channel::mpsc::channel(1000);

  let rpc_builder = {
		let client = client.clone();
		let pool = transaction_pool.clone();
		let network = network.clone();
		let sync_service = sync_service.clone();

		let is_authority = role.is_authority();
		let enable_dev_signer = eth_config.enable_dev_signer;
		let max_past_logs = eth_config.max_past_logs;
		let execute_gas_limit_multiplier = eth_config.execute_gas_limit_multiplier;
		let filter_pool = filter_pool.clone();
		let frontier_backend = frontier_backend.clone();
		let pubsub_notification_sinks = pubsub_notification_sinks.clone();
		let storage_override = storage_override.clone();
		let fee_history_cache = fee_history_cache.clone();
		let block_data_cache = Arc::new(fc_rpc::EthBlockDataCacheTask::new(
			task_manager.spawn_handle(),
			storage_override.clone(),
			eth_config.eth_log_block_cache,
			eth_config.eth_statuses_cache,
			prometheus_registry.clone(),
		));

    let slot_duration = babe_link.config().slot_duration();
		let target_gas_price = eth_config.target_gas_price;
		let pending_create_inherent_data_providers = move |_, ()| async move {
      let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

      let slot =
      sp_consensus_babe::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
        *timestamp,
        slot_duration,
      );

      Ok((slot, timestamp))
    };

		Box::new(move |deny_unsafe, subscription_task_executor| {
      let eth_deps = crate::rpc::eth::EthDeps {
				client: client.clone(),
				pool: pool.clone(),
				graph: pool.pool().clone(),
				converter: Some(TransactionConverter::default()),
				is_authority,
				enable_dev_signer,
				network: network.clone(),
				sync: sync_service.clone(),
				frontier_backend: match &*frontier_backend {
					fc_db::Backend::KeyValue(b) => b.clone(),
					fc_db::Backend::Sql(b) => b.clone(),
				},
				storage_override: storage_override.clone(),
				block_data_cache: block_data_cache.clone(),
				filter_pool: filter_pool.clone(),
				max_past_logs,
				fee_history_cache: fee_history_cache.clone(),
				fee_history_cache_limit,
				execute_gas_limit_multiplier,
				forced_parent_hashes: None,
				pending_create_inherent_data_providers,
      };

      let finality_proof_provider = sc_consensus_grandpa::FinalityProofProvider::new_for_service(
        backend.clone(),
        Some(shared_authority_set.clone()),
      );

      let deps = crate::rpc::FullDeps {
        client: client.clone(),
        pool: pool.clone(),
        select_chain: select_chain.clone(),
        chain_spec: config.chain_spec.cloned_box(),
        deny_unsafe,
        babe: babe_worker_handle.clone().map(|babe| crate::rpc::BabeDeps {
          babe_worker_handle: babe,
          keystore: keystore.clone(),
        }),
        grandpa: crate::rpc::GrandpaDeps {
          shared_voter_state: shared_voter_state.clone(),
          shared_authority_set: shared_authority_set.clone(),
          justification_stream: justification_stream.clone(),
          subscription_executor: subscription_task_executor.clone(), 
          finality_provider: finality_proof_provider.clone(),
        },
        backend: backend.clone(),
        is_authority,
        max_past_logs,
        network,
        command_sink: if cli.run.manual_seal {
          Some(command_sink.clone())
        } else {
          None
        },
        eth: eth_deps,
      };

			crate::rpc::create_full(
				deps,
				subscription_task_executor,
				pubsub_notification_sinks.clone(),
			)
			.map_err(Into::into)
		})
	};

  let (_rpc_handlers, telemetry_connection_notifier) = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
    config,
    backend,
    client: client.clone(),
    network: network.clone(),
    keystore: keystore_container.keystore(),
    rpc_builder: Box::new(rpc_builder),
    transaction_pool: transaction_pool.clone(),
    task_manager: &mut task_manager,
    system_rpc_tx,
    sync_service: sync_service.clone(),
    tx_handler_controller: None,
    telemetry: None,
  })?;

  // Spawn Frontier EthFilterApi maintenance task.
  if filter_pool.is_some() {
    // Each filter is allowed to stay in the pool for 100 blocks.
    const FILTER_RETAIN_THRESHOLD: u64 = 100;
    task_manager.spawn_essential_handle().spawn(
      "frontier-filter-pool",
      None,
      client.import_notification_stream().for_each(move |notification| {
        if let Ok(locked) = &mut filter_pool.clone().unwrap().lock() {
          let imported_number: u64 = notification.header.number as u64;
          for (k, v) in locked.clone().iter() {
            let lifespan_limit = v.at_block + FILTER_RETAIN_THRESHOLD;
            if lifespan_limit <= imported_number {
              locked.remove(&k);
            }
          }
        }
        futures::future::ready(())
      })
    );
  }

  // // Spawn Frontier pending transactions maintenance task (as essential, otherwise we leak).
  // if let Some(pending_transactions) = pending_transactions {
  //   const TRANSACTION_RETAIN_THRESHOLD: u64 = 15;
  //   task_manager.spawn_essential_handle().spawn(
  //     "frontier-pending-transactions",
  //     None,
  //     EthTask::pending_transaction_task(
	// 			Arc::clone(&client),
	// 				pending_transactions,
	// 				TRANSACTION_RETAIN_THRESHOLD,
	// 			)
  //   );
  // }

  let (block_import, grandpa_link, babe_link) = import_setup;

  (with_startup_data)(&block_import, &babe_link);

  spawn_frontier_tasks(
		&task_manager,
		client.clone(),
		backend,
		frontier_backend,
		filter_pool,
		storage_override,
		fee_history_cache,
		fee_history_cache_limit,
		sync_service.clone(),
		pubsub_notification_sinks,
	)
	.await;

  if role.is_authority() {
    let proposer = sc_basic_authorship::ProposerFactory::new(
      task_manager.spawn_handle(),
      client.clone(),  
      transaction_pool.clone(),
      prometheus_registry.as_ref(),
      telemetry.as_ref().map(|x| x.handle()),
    );

    let can_author_with =
      sp_consensus::CanAuthorWithNativeVersion::new(client.executor().clone());

    if manual_seal {
      let authorship_future = sc_consensus_manual_seal::run_manual_seal(
        ManualSealParams {
          block_import: frontier_block_import,
          env: proposer,
          client: client.clone(),
          pool: transaction_pool.pool().clone(),
          commands_stream,
          select_chain,
          consensus_data_provider: None,
          create_inherent_data_providers: move |_, ()| async move {
            Ok(sp_timestamp::InherentDataProvider::from_system_time())
          },
        } 
      );

      task_manager
          .spawn_essential_handle()
          .spawn_blocking("manual-seal", None, authorship_future);

      log::info!("Manual Seal Ready");

    } else {
		  let slot_duration = babe_link.config().slot_duration();
      let babe_config = sc_consensus_babe::BabeParams {
        keystore: keystore_container.sync_keystore(),
        client: client.clone(),
        select_chain,
        env: proposer,
        block_import,
        sync_oracle: network.clone(),
        force_authoring,
        backoff_authoring_blocks,
        babe_link,
        justification_sync_link: sync_service.clone(),
        create_inherent_data_providers: move |parent, ()| {
          let client_clone = client.clone();
          async move {
            let timestamp = sp_timestamp::InherentDataProvider::from_system_time();
            let slot = sp_consensus_babe::inherents::InherentDataProvider::from_timestamp_and_duration(
              *timestamp,
              slot_duration 
            ); 
            let storage_proof =
						sp_transaction_storage_proof::registration::new_data_provider(
							&*client_clone,
							&parent, 
						)?;
            
            Ok((slot, timestamp, storage_proof))
          }
        },
        block_proposal_slot_portion: SlotProportion::new(0.5),
        max_block_proposal_slot_portion: None,
        telemetry: telemetry.as_ref().map(|x| x.handle()),
      };

      let babe = sc_consensus_babe::start_babe(babe_config)?;

      task_manager.spawn_essential_handle().spawn_blocking("babe-proposer", None, babe);
    }
  }

  // Spawn authority discovery module.
  if role.is_authority() {
    let authority_discovery_role = sc_authority_discovery::Role::PublishAndDiscover(
      keystore_container.keystore(),
    );
    let dht_event_stream = network.event_stream("authority-discovery")
      .filter_map(|e| async move { match e {
        Event::Dht(e) => Some(e),
        _ => None,
      }});
    let (authority_discovery_worker, _service) = sc_authority_discovery::new_worker_and_service(
      client.clone(),
      network.clone(),
      Box::pin(dht_event_stream),
      authority_discovery_role,
      prometheus_registry.clone(),
    );

    task_manager.spawn_handle().spawn("authority-discovery-worker", None, authority_discovery_worker.run());
  }

  // if the node isn't actively participating in consensus then it doesn't
  // need a keystore, regardless of which protocol we use below.
  let keystore = if role.is_authority() {
    Some(keystore_container.sync_keystore())
  } else {
    None
  };

  let grandpa_config = sc_finality_grandpa::Config {
    // FIXME #1578 make this available through chainspec
    gossip_duration: Duration::from_millis(333),
    justification_generation_period: GRANDPA_JUSTIFICATION_PERIOD,
    name: Some(name),
    observer_enabled: false,
    keystore,
    local_role: role,
    telemetry: None,
    protocol_name: grandpa_protocol_name,
  };


  if enable_grandpa {
    // start the full GRANDPA voter
    // NOTE: non-authorities could run the GRANDPA observer protocol, but at
    // this point the full voter should provide better guarantees of block
    // and vote data availability than the observer. The observer has not
    // been tested extensively yet and having most nodes in a network run it
    // could lead to finality stalls.
    let grandpa_config = sc_finality_grandpa::GrandpaParams {
      config: grandpa_config,
      link: grandpa_link,
      network: network.clone(),
      voting_rule: sc_consensus_grandpa::VotingRulesBuilder::default().build(),
      prometheus_registry,
      shared_voter_state,
			sync: Arc::new(sync_service.clone()),
			telemetry: telemetry.as_ref().map(|x| x.handle()),
			offchain_tx_pool_factory: OffchainTransactionPoolFactory::new(transaction_pool.clone()),
			notification_service: grandpa_notification_service,
    };

    // the GRANDPA voter task is considered infallible, i.e.
    // if it fails we take down the service with it.
    task_manager.spawn_essential_handle().spawn_blocking(
      "grandpa-voter",
      None,
      sc_consensus_grandpa::run_grandpa_voter(grandpa_config)?
    );
  }

  network_starter.start_network();
  Ok(NewFullBase {
    task_manager,
    client,
    network,
    sync: sync_service,
    transaction_pool,
    rpc_handlers: _rpc_handlers,
  })
}

/// Builds a new service for a full client.
pub fn new_full(config: Configuration)
-> Result<TaskManager, ServiceError> {
  let mixnet_config = cli.mixnet_params.config(config.role.is_authority());
	let database_path = config.database.path().map(Path::to_path_buf);

  let task_manager = match config.network.network_backend {
		sc_network::config::NetworkBackendType::Libp2p => {
			let task_manager = new_full_base::<sc_network::NetworkWorker<_, _>>(
				config,
        &cli.run.eth,
				mixnet_config,
				cli.no_hardware_benchmarks,
				|_, _| (),
			)
			.map(|NewFullBase { task_manager, .. }| task_manager)?;
			task_manager
		},
		sc_network::config::NetworkBackendType::Litep2p => {
			let task_manager = new_full_base::<sc_network::Litep2pNetworkBackend>(
				config,
        &cli.run.eth,
				mixnet_config,
				cli.no_hardware_benchmarks,
				|_, _| (),
			)
			.map(|NewFullBase { task_manager, .. }| task_manager)?;
			task_manager
		},
	};

  // TODO: uncomment this when storage monitor is ready
	// if let Some(database_path) = database_path {
	// 	sc_storage_monitor::StorageMonitorService::try_spawn(
	// 		cli.storage_monitor,
	// 		database_path,
	// 		&task_manager.spawn_essential_handle(),
	// 	)
	// 	.map_err(|e| ServiceError::Application(e.into()))?;
	// }

  Ok(task_manager)
}

pub fn new_chain_ops(
	config: &mut Configuration,
  cli: &Cli,
) -> Result<
	(
		Arc<FullClient>,
		Arc<FullBackend>,
		BasicQueue<Block>,
		TaskManager,
		FrontierBackend<Block, FullClient>,
	),
	ServiceError,
> {
	config.keystore = sc_service::config::KeystoreConfig::InMemory;
	let PartialComponents {
		client,
		backend,
		import_queue,
		task_manager,
		other,
		..
	} = new_partial::<Block, RuntimeApi, HostFunctions, _>(
		config,
    cli,
		&cli.run.eth,
    None,
	)?;
	Ok((client, backend, import_queue, task_manager, other.3))
}
