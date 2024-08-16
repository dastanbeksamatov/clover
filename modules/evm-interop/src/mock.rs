// Copyright (C) 2021 Clover Network
// This file is part of Clover.

use super::*;
use crate as clover_evm_interop;

use frame_support::derive_impl;
use frame_support::parameter_types;
use sp_core::H160;
use sp_core::H256;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};

use std::str::FromStr;
use sp_runtime::BuildStorage;

parameter_types! {
    pub const BlockHashCount: u32 = 250;
}
#[derive_impl(frame_system::config_preludes::TestDefaultConfig as frame_system::DefaultConfig)]
impl frame_system::Config for Test {
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<u64>;
    type BlockHashCount = BlockHashCount;
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<u64>;
    type Block = Block;
}

parameter_types! {
    pub const ExistentialDeposit: u64 = 1;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig as pallet_balances::DefaultConfig)]
impl pallet_balances::Config for Test {
    type Balance = u64;
    type RuntimeEvent = RuntimeEvent;
    type ExistentialDeposit = ExistentialDeposit;
    type DustRemoval = ();
    type AccountStore = System;
    type RuntimeHoldReason = ();
}

impl Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type AddressMapping = AddressMappingHandler;
}

type Block = frame_system::mocking::MockBlock<Test>;

pub struct AddressMappingHandler;
impl AddressMapping<u64> for AddressMappingHandler {
    fn into_account_id(address: H160) -> u64 {
        match address {
            a if a == H160::from_str("2200000000000000000000000000000000000000").unwrap() => 8u64,
            a if a == H160::from_str("2200000000000000000000000000000000000001").unwrap() => 9u64,
            a if a == H160::from_str("2200000000000000000000000000000000000002").unwrap() => 10u64,
            a if a == H160::from_str("2200000000000000000000000000000000000003").unwrap() => 11u64,
            _ => 128u64,
        }
    }
}

frame_support::construct_runtime!(
  pub struct Test
  {
    System: frame_system,
    Balances: pallet_balances,
    CloverEvmInterOp: clover_evm_interop,
  }
);

// This function basically just builds a genesis storage key/value store according to
// our desired mockup.
pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();

    pallet_balances::GenesisConfig::<Test> {
        balances: vec![(4, 100_000_000), (5, 100_000_000)],
    }
    .assimilate_storage(&mut t)
    .unwrap();

    t.into()
}
