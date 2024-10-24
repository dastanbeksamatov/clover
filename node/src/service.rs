//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

use crate::cli::Cli;
use clover_primitives::Hash;
use clover_runtime::{self, opaque::Block, RuntimeApi};
use fc_consensus::FrontierBlockImport;
use fc_mapping_sync::kv::MappingSyncWorker;
use fc_rpc::EthTask;
use fc_rpc_core::types::FilterPool;
use futures::channel::mpsc::Receiver;
use futures::StreamExt;
use sc_cli::SubstrateCli;
use sc_client_api::{BlockchainEvents, ExecutorProvider};
use sc_consensus_babe::SlotProportion;
use sc_consensus_manual_seal::{EngineCommand, ManualSealParams};
use sc_executor::NativeElseWasmExecutor;
use sc_network::Event;
use sc_service::{error::Error as ServiceError, BasePath, Configuration, RpcHandlers, TaskManager};
use sc_telemetry::{TelemetryConnectionNotifier, TelemetryWorker};
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sp_runtime::traits::Block as BlockT;
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
    time::Duration,
};

/// The minimum period of blocks on which justifications will be
/// imported and generated.
const GRANDPA_JUSTIFICATION_PERIOD: u32 = 512;

// Declare an instance of the native executor named `ExecutorDispatch`. Include the wasm binary as
// the equivalent wasm code.
pub struct ExecutorDispatch;

impl sc_executor::NativeExecutionDispatch for ExecutorDispatch {
    type ExtendHostFunctions = ();

    fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
        clover_runtime::api::dispatch(method, data)
    }

    fn native_version() -> sc_executor::NativeVersion {
        clover_runtime::native_version()
    }
}

type FullClient =
    sc_service::TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<ExecutorDispatch>>;
type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;
type FullGrandpaBlockImport =
    sc_consensus_grandpa::GrandpaBlockImport<FullBackend, Block, FullClient, FullSelectChain>;
type LightClient =
    sc_service::TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<ExecutorDispatch>>;

pub fn open_frontier_backend(config: &Configuration) -> Result<Arc<fc_db::Backend<Block>>, String> {
    let config_dir = config
        .base_path
        .as_ref()
        .map(|base_path| base_path.config_dir(config.chain_spec.id()))
        .unwrap_or_else(|| {
            BasePath::from_project("", "", &crate::cli::Cli::executable_name())
                .config_dir(config.chain_spec.id())
        });
    let database_dir = config_dir.join("frontier").join("db");

    Ok(Arc::new(fc_db::Backend::<Block>::new(
        &fc_db::DatabaseSettings {
            source: fc_db::DatabaseSettingsSrc::RocksDb {
                path: database_dir,
                cache_size: 0,
            },
        },
    )?))
}

pub fn new_partial(
    config: &Configuration,
    cli: &Cli,
) -> Result<
    sc_service::PartialComponents<
        FullClient,
        FullBackend,
        FullSelectChain,
        sp_consensus::DefaultImportQueue<Block, FullClient>,
        sc_transaction_pool::FullPool<Block, FullClient>,
        (
            impl Fn(
                crate::rpc::DenyUnsafe,
                crate::rpc::SubscriptionTaskExecutor,
                Arc<sc_network::NetworkService<Block, clover_primitives::Hash>>,
            ) -> crate::rpc::IoHandler,
            (
                sc_consensus_babe::BabeBlockImport<
                    Block,
                    FullClient,
                    FrontierBlockImport<Block, FullGrandpaBlockImport, FullClient>,
                >,
                sc_consensus_grandpa::LinkHalf<Block, FullClient, FullSelectChain>,
                sc_consensus_babe::BabeLink<Block>,
            ),
            (
                sc_consensus_grandpa::SharedVoterState,
                PendingTransactions,
                Option<FilterPool>,
                Arc<fc_db::Backend<Block>>,
                Receiver<EngineCommand<Hash>>,
                FrontierBlockImport<Block, FullGrandpaBlockImport, FullClient>,
            ),
        ),
    >,
    ServiceError,
> {
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

    let executor = sc_service::new_native_or_wasm_executor(&config);

    let (client, backend, keystore_container, task_manager) =
        sc_service::new_full_parts::<Block, RuntimeApi, Executor>(
            &config,
            telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
            executor,
        )?;
    let client = Arc::new(client);

    let select_chain = sc_consensus::LongestChain::new(backend.clone());

    let transaction_pool = sc_transaction_pool::BasicPool::new_full(
        config.transaction_pool.clone(),
        config.role.is_authority().into(),
        config.prometheus_registry(),
        task_manager.spawn_handle(),
        client.clone(),
    );

    let filter_pool: Option<FilterPool> = Some(Arc::new(Mutex::new(BTreeMap::new())));

    let frontier_backend = open_frontier_backend(config)?;

    let manual_seal = cli.run.manual_seal;

    if manual_seal {
        inherent_data_providers
            .register_provider(sp_timestamp::InherentDataProvider)
            .map_err(Into::into)
            .map_err(sp_consensus::error::Error::InherentData)?;
    }

    let (command_sink, commands_stream) = futures::channel::mpsc::channel(1000);

    let (grandpa_block_import, grandpa_link) = sc_consensus_grandpa::block_import(
        client.clone(),
        GRANDPA_JUSTIFICATION_PERIOD,
        &(client.clone() as Arc<_>),
        select_chain.clone(),
        telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
    )?;

    let justification_import = grandpa_block_import.clone();
    let frontier_block_import =
        FrontierBlockImport::new(grandpa_block_import.clone(), client.clone());

    let (block_import, babe_link) = sc_consensus_babe::block_import(
        sc_consensus_babe::Config::get_or_compute(&*client)?,
        frontier_block_import.clone(),
        client.clone(),
    )?;

    let import_queue = if manual_seal {
        sc_consensus_manual_seal::import_queue(
            Box::new(frontier_block_import.clone()),
            &task_manager.spawn_handle(),
            config.prometheus_registry(),
        )
    } else {
        sc_consensus_babe::import_queue(sc_consensus_babe::ImportQueueParams {
            link: babe_link.clone(),
            block_import: block_import.clone(),
            justification_import: justification_import.clone(),
            client: client.clone(),
            select_chain: select_chain.clone(),
            create_inherent_data_providers: (),
            spawner: &task_manager.spawn_handle(),
            registry: config.prometheus_registry(),
            telemetry: telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
            offchain_tx_pool_factory: OffchainTransactionPoolFactory::new(client.clone()),
        })?
    };

    let import_setup = (block_import, grandpa_link, babe_link);

    let (rpc_extensions_builder, rpc_setup) = {
        let (_, grandpa_link, babe_link) = &import_setup;
        let justification_stream = grandpa_link.justification_stream();
        let shared_authority_set = grandpa_link.shared_authority_set().clone();
        let shared_voter_state = sc_consensus_grandpa::SharedVoterState::empty();
        let rpc_setup = shared_voter_state.clone();

        let finality_proof_provider = sc_consensus_grandpa::FinalityProofProvider::new_for_service(
            backend.clone(),
            Some(shared_authority_set.clone()),
        );

        let babe_config = babe_link.config().clone();
        let shared_epoch_changes = babe_link.epoch_changes().clone();

        let client = client.clone();
        let pool = transaction_pool.clone();
        let select_chain = select_chain.clone();
        let keystore = keystore_container.sync_keystore();
        let chain_spec = config.chain_spec.cloned_box();
        let is_authority = config.role.is_authority();
        let subscription_task_executor =
            sc_rpc::SubscriptionTaskExecutor::new(task_manager.spawn_handle());

        let filter_pool_clone = filter_pool.clone();
        let backend = frontier_backend.clone();
        let max_past_logs = cli.run.max_past_logs;

        let rpc_extensions_builder = move |deny_unsafe, _subscription_executor: sc_rpc::SubscriptionTaskExecutor, network: Arc<sc_network::NetworkService<Block, <Block as BlockT>::Hash>>| {

          let deps = crate::rpc::FullDeps {
            client: client.clone(),
            pool: pool.clone(),
            select_chain: select_chain.clone(),
            chain_spec: chain_spec.cloned_box(),
            deny_unsafe,
            babe: crate::rpc::BabeDeps {
              babe_config: babe_config.clone(),
              shared_epoch_changes: shared_epoch_changes.clone(),
              keystore: keystore.clone(),
            },
            grandpa: crate::rpc::GrandpaDeps {
              shared_voter_state: shared_voter_state.clone(),
              shared_authority_set: shared_authority_set.clone(),
              justification_stream: justification_stream.clone(),
              subscription_executor: _subscription_executor.clone(),
              finality_provider: finality_proof_provider.clone(),
            },
            filter_pool: filter_pool_clone.clone(),
            backend: backend.clone(),
            is_authority,
            max_past_logs,
            network: network,
            command_sink: if manual_seal {
              Some(command_sink.clone())
            } else {
              None
            },
          };

          crate::rpc::create_full(deps, subscription_task_executor.clone())
        };

        (rpc_extensions_builder, rpc_setup)
    };

    Ok(sc_service::PartialComponents {
        client,
        backend,
        task_manager,
        keystore_container,
        select_chain,
        import_queue,
        transaction_pool,
        other: (
            rpc_extensions_builder,
            import_setup,
            (
                rpc_setup,
                filter_pool,
                frontier_backend,
                commands_stream,
                frontier_block_import,
            ),
        ),
    })
}

/// Builds a new service for a full client.
pub fn new_full_base(
    mut config: Configuration,
    cli: &Cli,
    with_startup_data: impl FnOnce(
        &sc_consensus_babe::BabeBlockImport<
            Block,
            FullClient,
            FrontierBlockImport<Block, FullGrandpaBlockImport, FullClient>,
        >,
        &sc_consensus_babe::BabeLink<Block>,
    ),
) -> Result<
    (
        TaskManager,
        Arc<FullClient>,
        Arc<sc_network::NetworkService<Block, <Block as BlockT>::Hash>>,
        Arc<sc_transaction_pool::FullPool<Block, FullClient>>,
    ),
    ServiceError,
> {
    let sc_service::PartialComponents {
        client,
        backend,
        mut task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other:
            (
                partial_rpc_extensions_builder,
                import_setup,
                (rpc_setup, filter_pool, frontier_backend, commands_stream, frontier_block_import),
            ),
    } = new_partial(&config, cli)?;

    let shared_voter_state = rpc_setup;
    let mut net_config = sc_network::config::FullNetworkConfiguration::new(&config.network);

    let grandpa_protocol_name = sc_consensus_grandpa::protocol_standard_name(
        &client
            .block_hash(0)
            .ok()
            .flatten()
            .expect("Genesis block exists; qed"),
        &config.chain_spec,
    );
    net_config.add_notification_protocol(sc_consensus_grandpa::grandpa_peers_set_config(
        grandpa_protocol_name.clone(),
    ));

    config
        .network
        .extra_sets
        .push(sc_consensus_grandpa::grandpa_peers_set_config(
            grandpa_protocol_name.clone(),
        ));

    #[cfg(feature = "cli")]
    config.network.request_response_protocols.push(
        sc_finality_grandpa_warp_sync::request_response_config_for_chain(
            &config,
            task_manager.spawn_handle(),
            backend.clone(),
        ),
    );

    let warp_sync = Arc::new(sc_consensus_grandpa::warp_proof::NetworkProvider::new(
        backend.clone(),
        import_setup.1.shared_authority_set().clone(),
        Vec::default(),
    ));

    let (network, system_rpc_tx, transaction_handler_controller, network_starter, sync_service) =
        sc_service::build_network(sc_service::BuildNetworkParams {
            config: &config,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            spawn_handle: task_manager.spawn_handle(),
            import_queue,
            block_announce_validator_builder: None,
            net_config,
            warp_sync_params: Some(sc_service::WarpSyncParams::WithProvider(warp_sync)),
            block_relay: None,
        })?;

    if config.offchain_worker.enabled {
        sc_service::build_offchain_workers(
            &config,
            backend.clone(),
            task_manager.spawn_handle(),
            client.clone(),
            network.clone(),
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

    let rpc_extensions_builder = move |deny_unsafe, subscription_executor| {
        partial_rpc_extensions_builder(deny_unsafe, subscription_executor, network_clone.clone())
    };

    // task_manager.spawn_essential_handle().spawn(
    //     "frontier-mapping-sync-worker",
    //     MappingSyncWorker::new(
    //         client.import_notification_stream(),
    //         Duration::new(6, 0),
    //         client.clone(),
    //         backend.clone(),
    //         frontier_backend.clone(),
    //         retry_times,
    //         sync_from,
    //         strategy,
    //         sync_oracle,
    //         pubsub_notification_sinks,
    //     )
    //     .for_each(|()| futures::future::ready(())),
    // );

    let (_rpc_handlers, telemetry_connection_notifier) =
        sc_service::spawn_tasks(sc_service::SpawnTasksParams {
            config,
            backend,
            client: client.clone(),
            network: network.clone(),
            keystore: keystore_container.sync_keystore(),
            transaction_pool: transaction_pool.clone(),
            task_manager: &mut task_manager,
            system_rpc_tx,
            rpc_builder: rpc_extensions_builder,
            tx_handler_controller: transaction_handler_controller,
            sync_service: Arc::new(sync_service.clone()),
            telemetry: telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
        })?;

    // Spawn Frontier EthFilterApi maintenance task.
    if filter_pool.is_some() {
        // Each filter is allowed to stay in the pool for 100 blocks.
        const FILTER_RETAIN_THRESHOLD: u64 = 100;
        task_manager.spawn_essential_handle().spawn(
            "frontier-filter-pool",
            "filter-pool",
            client
                .import_notification_stream()
                .for_each(move |notification| {
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
                }),
        );
    }

    let (block_import, grandpa_link, babe_link) = import_setup;

    (with_startup_data)(&block_import, &babe_link);

    if role.is_authority() {
        let proposer = sc_basic_authorship::ProposerFactory::new(
            task_manager.spawn_handle(),
            client.clone(),
            transaction_pool.clone(),
            prometheus_registry.as_ref(),
            telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
        );

        let manual_seal = cli.run.manual_seal;

        if manual_seal {
            let authorship_future = sc_consensus_manual_seal::run_manual_seal(ManualSealParams {
                block_import: frontier_block_import,
                env: proposer,
                client: client.clone(),
                pool: transaction_pool.pool().clone(),
                commands_stream,
                select_chain,
                consensus_data_provider: None,
                create_inherent_data_providers: move || async move {
                    let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

                    let slot =
                    sp_consensus_babe::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
                    *timestamp,
                    slot_duration,
                    );

                    Ok((slot, timestamp))
                },
            });

            task_manager.spawn_essential_handle().spawn_blocking(
                "manual-seal",
                "manual-seal",
                authorship_future,
            );

            log::info!("Manual Seal Ready");
        } else {
            let can_author_with =
                sp_consensus::CanAuthorWithNativeVersion::new(client.executor().clone());

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
                create_inherent_data_providers: move |parent, ()| {
                    let client_clone = client_clone.clone();
                    async move {
                        let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

                        let slot =
                      sp_consensus_babe::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
                        *timestamp,
                        slot_duration,
                      );

                        // let storage_proof =
                        //     sp_transaction_storage_proof::registration::new_data_provider(
                        //         &*client_clone,
                        //         &parent,
                        //     )?;

                        Ok((slot, timestamp))
                    }
                },
                telemetry: telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
                justification_sync_link: babe_link.clone(),
                block_proposal_slot_portion: SlotProportion::new(0.5),
                max_block_proposal_slot_portion: None,
            };

            let babe = sc_consensus_babe::start_babe(babe_config)?;

            task_manager
                .spawn_essential_handle()
                .spawn_blocking("babe-proposer", "proposer", babe);
        }
    }

    // Spawn authority discovery module.
    if role.is_authority() {
        let authority_discovery_role =
            sc_authority_discovery::Role::PublishAndDiscover(keystore_container.keystore());
        let dht_event_stream =
            network
                .event_stream("authority-discovery")
                .filter_map(|e| async move {
                    match e {
                        Event::Dht(e) => Some(e),
                        _ => None,
                    }
                });
        let (authority_discovery_worker, _service) = sc_authority_discovery::new_worker_and_service(
            client.clone(),
            network.clone(),
            Box::pin(dht_event_stream),
            authority_discovery_role,
            prometheus_registry.clone(),
        );

        task_manager.spawn_handle().spawn(
            "authority-discovery-worker",
            "authority-discovery-worker",
            authority_discovery_worker.run(),
        );
    }

    // if the node isn't actively participating in consensus then it doesn't
    // need a keystore, regardless of which protocol we use below.
    let keystore = if role.is_authority() {
        Some(keystore_container.sync_keystore())
    } else {
        None
    };

    let grandpa_config = sc_consensus_grandpa::Config {
        // FIXME #1578 make this available through chainspec
        gossip_duration: Duration::from_millis(333),
        justification_generation_period: GRANDPA_JUSTIFICATION_PERIOD,
        name: Some(name),
        observer_enabled: false,
        keystore,
        local_role: role.clone(),
        telemetry: telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
        protocol_name: grandpa_protocol_name,
    };

    if enable_grandpa {
        // start the full GRANDPA voter
        // NOTE: non-authorities could run the GRANDPA observer protocol, but at
        // this point the full voter should provide better guarantees of block
        // and vote data availability than the observer. The observer has not
        // been tested extensively yet and having most nodes in a network run it
        // could lead to finality stalls.
        let grandpa_config = sc_consensus_grandpa::GrandpaParams {
            config: grandpa_config,
            link: grandpa_link,
            network: network.clone(),
            voting_rule: sc_consensus_grandpa::VotingRulesBuilder::default().build(),
            prometheus_registry,
            shared_voter_state,
            telemetry: telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
            offchain_tx_pool_factory: OffchainTransactionPoolFactory::new(client.clone()),
            sync: Arc::new(sync_service.clone()),
        };

        // the GRANDPA voter task is considered infallible, i.e.
        // if it fails we take down the service with it.
        task_manager.spawn_essential_handle().spawn_blocking(
            "grandpa-voter",
            "grandpa-voter",
            sc_consensus_grandpa::run_grandpa_voter(grandpa_config)?,
        );
    }

    network_starter.start_network();
    Ok((
        task_manager,
        inherent_data_providers,
        client,
        network,
        transaction_pool,
    ))
}

/// Builds a new service for a full client.
pub fn new_full(config: Configuration, cli: &Cli) -> Result<TaskManager, ServiceError> {
    new_full_base(config, cli, |_, _| ()).map(|(task_manager, _, _, _, _)| task_manager)
}

pub fn new_light_base(
    config: Configuration,
) -> Result<
    (
        TaskManager,
        RpcHandlers,
        Option<TelemetryConnectionNotifier>,
        Arc<LightClient>,
        Arc<sc_network::NetworkService<Block, <Block as BlockT>::Hash>>,
        Arc<
            sc_transaction_pool::LightPool<Block, LightClient, sc_network::config::OnDemand<Block>>,
        >,
    ),
    ServiceError,
> {
    let (client, backend, keystore_container, mut task_manager, on_demand) =
        sc_service::new_light_parts::<Block, RuntimeApi, Executor>(&config)?;

    let select_chain = sc_consensus::LongestChain::new(backend.clone());

    let transaction_pool = Arc::new(sc_transaction_pool::BasicPool::new_light(
        config.transaction_pool.clone(),
        config.prometheus_registry(),
        task_manager.spawn_handle(),
        client.clone(),
        on_demand.clone(),
    ));

    let (grandpa_block_import, _) = sc_consensus_grandpa::block_import(
        client.clone(),
        GRANDPA_JUSTIFICATION_PERIOD,
        &(client.clone() as Arc<_>),
        select_chain.clone(),
        telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
    )?;

    let justification_import = grandpa_block_import.clone();

    let (babe_block_import, babe_link) = sc_consensus_babe::block_import(
        sc_consensus_babe::Config::get_or_compute(&*client)?,
        grandpa_block_import,
        client.clone(),
    )?;

    let import_queue = sc_consensus_babe::import_queue(sc_consensus_babe::ImportQueueParams {
        link: babe_link.clone(),
        block_import: babe_block_import,
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
        spawner: task_manager.spawn_handle(),
        registry: config.prometheus_registry(),
        telemetry: None,
        offchain_tx_pool_factory: OffchainTransactionPoolFactory::new(client.clone()),
    });

    let warp_sync = Arc::new(sc_consensus_grandpa::warp_proof::NetworkProvider::new(
        backend.clone(),
        import_setup.1.shared_authority_set().clone(),
        Vec::default(),
    ));

    let (network, system_rpc_tx, transaction_handler_controller, network_starter, sync_service) =
        sc_service::build_network(sc_service::BuildNetworkParams {
            config: &config,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            spawn_handle: task_manager.spawn_handle(),
            import_queue,
            block_announce_validator_builder: None,
            net_config: NetworkConfig::new(config.chain_spec()),
            warp_sync_params: Some(sc_service::WarpSyncParams::WithProvider(warp_sync)),
            block_relay: None,
        })?;

    network_starter.start_network();

    if config.offchain_worker.enabled {
        sc_service::build_offchain_workers(
            &config,
            backend.clone(),
            task_manager.spawn_handle(),
            client.clone(),
            network.clone(),
        );
    }

    let light_deps = crate::rpc::LightDeps {
        remote_blockchain: backend.remote_blockchain(),
        fetcher: on_demand.clone(),
        client: client.clone(),
        pool: transaction_pool.clone(),
    };

    let rpc_extensions = crate::rpc::create_light(light_deps);

    let (rpc_handlers, telemetry_connection_notifier) =
        sc_service::spawn_tasks(sc_service::SpawnTasksParams {
            rpc_builder: Box::new(sc_service::NoopRpcExtensionBuilder(rpc_extensions)),
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            keystore: keystore_container.sync_keystore(),
            config,
            backend,
            system_rpc_tx,
            network: network.clone(),
            task_manager: &mut task_manager,
            tx_handler_controller: transaction_handler_controller,
            sync_service: sync_service,
            telemetry: telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
        })?;

    Ok((
        task_manager,
        rpc_handlers,
        telemetry_connection_notifier,
        client,
        network,
        transaction_pool,
    ))
}

/// Builds a new service for a light client.
pub fn new_light(config: Configuration) -> Result<TaskManager, ServiceError> {
    new_light_base(config).map(|(task_manager, _, _, _, _, _)| task_manager)
}
