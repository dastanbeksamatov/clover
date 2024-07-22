#![cfg_attr(not(feature = "std"), no_std)]

sp_api::decl_runtime_apis! {
	pub trait CurrencyBalanceApi<AccountId, CurrencyId, Balance> where
		AccountId: parity_scale_codec::Codec,
        CurrencyId: parity_scale_codec::Codec,
        Balance: parity_scale_codec::Codec {
		// Get account balance of a currency
		fn account_balance(account: AccountId, currency_id: Option<CurrencyId>) -> sp_std::vec::Vec<(CurrencyId, Balance)>;
	}

	pub trait CurrencyPairApi<> {
		fn currency_pair() -> sp_std::vec::Vec<(clover_primitives::CurrencyId, clover_primitives::CurrencyId)>;
	}

	pub trait CurrencyExchangeApi<AccountId, CurrencyId, Balance, Rate, Share> where
		AccountId: parity_scale_codec::Codec,
		CurrencyId: parity_scale_codec::Codec,
		Balance: parity_scale_codec::Codec,
		Rate: parity_scale_codec::Codec,
		Share: parity_scale_codec::Codec, {
		fn target_amount_available(source: CurrencyId, target: CurrencyId, amount: Balance) -> (Balance, sp_std::vec::Vec<CurrencyId>);
		fn supply_amount_needed(source: CurrencyId, target: CurrencyId, amount: Balance) -> (Balance, sp_std::vec::Vec<CurrencyId>);

		fn get_liquidity(account: Option<AccountId>) -> sp_std::vec::Vec<(CurrencyId, CurrencyId, Balance, Balance, Balance, Balance, Balance)>;
		fn get_exchange_rate() -> Rate;
		fn to_add_liquidity(source: CurrencyId, target: CurrencyId, source_amount: Balance, target_amount: Balance) -> (Share, Share);
    fn get_staking_info(account: AccountId, currency_first: CurrencyId, currency_second: CurrencyId) -> (Share, Balance);
	}

  pub trait IncentivePoolApi<AccountId, CurrencyId, Balance, Share> where
    AccountId: parity_scale_codec::Codec,
    CurrencyId: parity_scale_codec::Codec,
    Balance: parity_scale_codec::Codec,
    Share: parity_scale_codec::Codec, {
    fn get_all_incentive_pools() -> sp_std::vec::Vec<(CurrencyId, CurrencyId, Share, Balance)>;
  }
}
