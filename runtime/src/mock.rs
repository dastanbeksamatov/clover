#![cfg(test)]

use frame_support::derive_impl;

use super::*;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestRuntime;

#[derive_impl(frame_system::config_preludes::TestDefaultConfig as frame_system::DefaultConfig)]
impl frame_system::Config for TestRuntime {
    type Block = Block;
    type AccountId = AccountId;
    type Lookup = Indices;
    type Nonce = Index;
    type Hash = Hash;
    type AccountData = pallet_balances::AccountData<Balance>;
}

pub const ALICE: [u8; 32] = [0u8; 32];
pub const BOB: [u8; 32] = [1u8; 32];
pub const DAVE: [u8; 32] = [2u8; 32];
pub const CLV: CurrencyId = CurrencyId::CLV;

pub struct ExtBuilder {
    endowed_accounts: Vec<(AccountId, CurrencyId, Balance)>,
}

impl Default for ExtBuilder {
    fn default() -> Self {
        Self {
            endowed_accounts: vec![],
        }
    }
}

impl ExtBuilder {
    pub fn balances(mut self, endowed_accounts: Vec<(AccountId, CurrencyId, Balance)>) -> Self {
        self.endowed_accounts = endowed_accounts;
        self
    }

    pub fn build(self) -> sp_io::TestExternalities {
        let mut t = frame_system::GenesisConfig::default()
            .build_storage()
            .unwrap();

        pallet_balances::GenesisConfig::<Runtime> {
            balances: self
                .endowed_accounts
                .clone()
                .into_iter()
                .filter(|(_, currency_id, _)| *currency_id == CLV)
                // the balance of any account should always be more than existential deposit.
                .map(|(account_id, _, _initial_balance)| (account_id, 500))
                .collect::<Vec<_>>(),
        }
        .assimilate_storage(&mut t)
        .unwrap();

        pallet_membership::GenesisConfig::<Runtime, pallet_membership::Instance1> {
            members: vec![
                AccountId::from(ALICE),
                AccountId::from(BOB),
                AccountId::from(DAVE),
            ]
            .try_into()
            .unwrap(),
            phantom: Default::default(),
        }
        .assimilate_storage(&mut t)
        .unwrap();

        t.into()
    }
}
