// This file is part of Substrate.

// Copyright (C) 2017-2020 Parity Technologies (UK) Ltd.
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
use crate::chain_spec;
use crate::cli::{Cli, Subcommand};
use crate::service;
use sc_cli::{SubstrateCli, RuntimeVersion, Role, ChainSpec};
use sc_service::PartialComponents;
use crate::service::new_partial;

impl SubstrateCli for Cli {
  fn impl_name() -> String {
    "Clover Node".into()
  }

  fn impl_version() -> String {
    env!("SUBSTRATE_CLI_IMPL_VERSION").into()
  }

  fn description() -> String {
    env!("CARGO_PKG_DESCRIPTION").into()
  }

  fn author() -> String {
    env!("CARGO_PKG_AUTHORS").into()
  }

  fn support_url() -> String {
    "support.anonymous.an".into()
  }

  fn copyright_start_year() -> i32 {
    2017
  }

  fn load_spec(&self, id: &str) -> Result<Box<dyn sc_service::ChainSpec>, String> {
    Ok(match id {
      "dev" => Box::new(chain_spec::development_config()?),
      "" | "local" => Box::new(chain_spec::local_testnet_config()?),
      "rose" => Box::new(chain_spec::local_rose_testnet_config()?),
      "iris" => Box::new(chain_spec::iris_testnet_config()?),
      "ivy" => Box::new(chain_spec::ivy_config()?),
      path => Box::new(chain_spec::ChainSpec::from_json_file(
        std::path::PathBuf::from(path),
      )?),
    })
  }
}

/// Parse and run command line arguments
#[allow(dead_code)]
pub fn run() -> sc_cli::Result<()> {
  let cli = Cli::from_args();

  match &cli.subcommand {
    Some(Subcommand::Key(cmd)) => cmd.run(&cli),
    Some(Subcommand::Sign(cmd)) => cmd.run(),
    Some(Subcommand::Verify(cmd)) => cmd.run(),
    Some(Subcommand::Vanity(cmd)) => cmd.run(),
    Some(Subcommand::BuildSpec(cmd)) => {
      let runner = cli.create_runner(cmd)?;
      runner.sync_run(|config| cmd.run(config.chain_spec, config.network))
    }
    Some(Subcommand::CheckBlock(cmd)) => {
      let runner = cli.create_runner(cmd)?;
      runner.async_run(|config| {
        let PartialComponents { client, task_manager, import_queue, .. }
        = new_partial(&config, &cli, &cli.run.eth, None)?;
        Ok((cmd.run(client, import_queue), task_manager))
      })
    }
    Some(Subcommand::ExportBlocks(cmd)) => {
      let runner = cli.create_runner(cmd)?;
      runner.async_run(|config| {
        let PartialComponents { client, task_manager, ..}
        = new_partial(&config, &cli, &cli.run.eth, None)?;
        Ok((cmd.run(client, config.database), task_manager))
      })
    }

    Some(Subcommand::ExportState(cmd)) => {
      let runner = cli.create_runner(cmd)?;
      runner.async_run(|config| {
        let PartialComponents { client, task_manager, ..}
        = new_partial(&config, &cli, &cli.run.eth, None)?;
        Ok((cmd.run(client, config.chain_spec), task_manager))
      })
    }

    Some(Subcommand::ImportBlocks(cmd)) => {
      let runner = cli.create_runner(cmd)?;

      runner.async_run(|config| {
        let PartialComponents{client, import_queue, task_manager, ..} = new_partial(&config, &cli, &cli.run.eth, None)?;

        Ok((cmd.run(client, import_queue), task_manager))
      })
    }

    Some(Subcommand::PurgeChain(cmd)) => {
      let runner = cli.create_runner(cmd)?;
      runner.sync_run(|config| cmd.run(config.database))
    }

    Some(Subcommand::Revert(cmd)) => {
      let runner = cli.create_runner(cmd)?;

      runner.async_run(|config| {
        let PartialComponents { client, task_manager, backend, ..}
        = new_partial(&config, &cli, &cli.run.eth, None)?;
        let aux_revert = Box::new(move |client, _, blocks| {
					sc_consensus_grandpa::revert(client, blocks)?;
					Ok(())
				});
        Ok((cmd.run(client, backend, Some(aux_revert)), task_manager))
      })
    }
    Some(Subcommand::FrontierDb(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.sync_run(|mut config| {
				let (client, _, _, _, frontier_backend) =
					service::new_chain_ops(&mut config, &cli)?;
				let frontier_backend = match frontier_backend {
					fc_db::Backend::KeyValue(kv) => kv,
					_ => panic!("Only fc_db::Backend::KeyValue supported"),
				};
				cmd.run(client, frontier_backend)
			})
		}
    None => {
			let runner = cli.create_runner(&cli.run)?;
			runner.run_node_until_exit(|config| async move {
				service::new_full(config, &cli).map_err(sc_cli::Error::Service)
			})
    }
  }
}
