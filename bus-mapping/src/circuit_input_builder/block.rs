//! Block-related utility module

use super::{
    execution::ExecState, transaction::Transaction, CopyEvent, ExecStep, ExpEvent, Withdrawal,
};
use crate::{
    operation::{OperationContainer, RWCounter},
    Error,
};
use axiom_eth::storage::circuit::EthBlockStorageInput;
use eth_types::{evm_unimplemented, Address, Word, H256};
use itertools::Itertools;
use std::collections::HashMap;

/// Context of a [`Block`] which can mutate in a [`Transaction`].
#[derive(Debug, Clone)]
pub struct BlockContext {
    /// Used to track the global counter in every operation in the block.
    /// Contains the next available value.
    pub(crate) rwc: RWCounter,
    /// Map call_id to (tx_index, call_index) (where tx_index is the index used
    /// in Block.txs and call_index is the index used in Transaction.
    /// calls).
    pub(crate) call_map: HashMap<usize, (usize, usize)>,
    /// Total gas used by previous transactions in this block.
    pub(crate) cumulative_gas_used: u64,
}

impl Default for BlockContext {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockContext {
    /// Create a new Self
    pub fn new() -> Self {
        Self {
            rwc: RWCounter::new(),
            call_map: HashMap::new(),
            cumulative_gas_used: 0,
        }
    }
}

/// Block-wise execution steps that don't belong to any Transaction.
#[derive(Debug)]
pub struct BlockSteps {
    /// EndBlock step that is repeated after the last transaction and before
    /// reaching the last EVM row.
    pub end_block_not_last: ExecStep,
    /// Last EndBlock step that appears in the last EVM row.
    pub end_block_last: ExecStep,
}

// TODO: Remove fields that are duplicated in`eth_block`
/// Circuit Input related to a block.
#[derive(Debug)]
pub struct Block {
    /// chain id
    pub chain_id: Word,
    /// history hashes contains most recent 256 block hashes in history, where
    /// the lastest one is at history_hashes[history_hashes.len() - 1].
    pub history_hashes: Vec<Word>,
    /// coinbase
    pub coinbase: Address,
    /// gas limit
    pub gas_limit: u64,
    /// number
    pub number: Word,
    /// time
    pub timestamp: Word,
    /// difficulty
    pub difficulty: Word,
    /// base fee
    pub base_fee: Word,
    /// State root of the previous block
    pub prev_state_root: Word,
    /// Container of operations done in this block.
    pub container: OperationContainer,
    /// Transactions contained in the block
    pub txs: Vec<Transaction>,
    /// Block-wise steps
    pub block_steps: BlockSteps,
    /// Copy events in this block.
    pub copy_events: Vec<CopyEvent>,
    /// Inputs to the SHA3 opcode
    pub sha3_inputs: Vec<Vec<u8>>,
    /// Exponentiation events in the block.
    pub exp_events: Vec<ExpEvent>,
    /// Original block from geth
    pub eth_block: eth_types::Block<eth_types::Transaction>,
    /// Axiom Inputs
    pub axiom_inputs: EthBlockStorageInput,
}

impl Block {
    /// Create a new block.
    pub fn new(
        chain_id: Word,
        history_hashes: Vec<Word>,
        prev_state_root: Word,
        eth_block: &eth_types::Block<eth_types::Transaction>,
        axiom_inputs: EthBlockStorageInput,
    ) -> Result<Self, Error> {
        if eth_block.base_fee_per_gas.is_none() {
            // FIXME: resolve this once we have proper EIP-1559 support
            evm_unimplemented!(
                "This does not look like a EIP-1559 block - base_fee_per_gas defaults to zero"
            );
        }

        Ok(Self {
            chain_id,
            history_hashes,
            coinbase: eth_block
                .author
                .ok_or(Error::EthTypeError(eth_types::Error::IncompleteBlock))?,
            gas_limit: eth_block.gas_limit.low_u64(),
            number: eth_block
                .number
                .ok_or(Error::EthTypeError(eth_types::Error::IncompleteBlock))?
                .low_u64()
                .into(),
            timestamp: eth_block.timestamp,
            difficulty: if eth_block.difficulty.is_zero() {
                eth_block
                    .mix_hash
                    .unwrap_or_default()
                    .to_fixed_bytes()
                    .into()
            } else {
                eth_block.difficulty
            },
            base_fee: eth_block.base_fee_per_gas.unwrap_or_default(),
            prev_state_root,
            container: OperationContainer::new(),
            txs: Vec::new(),
            block_steps: BlockSteps {
                end_block_not_last: ExecStep {
                    exec_state: ExecState::EndBlock,
                    ..ExecStep::default()
                },
                end_block_last: ExecStep {
                    exec_state: ExecState::EndBlock,
                    ..ExecStep::default()
                },
            },
            copy_events: Vec::new(),
            exp_events: Vec::new(),
            sha3_inputs: Vec::new(),
            eth_block: eth_block.clone(),
            axiom_inputs,
        })
    }

    /// Return the list of transactions of this block.
    pub fn txs(&self) -> &[Transaction] {
        &self.txs
    }

    #[cfg(test)]
    pub fn txs_mut(&mut self) -> &mut Vec<Transaction> {
        &mut self.txs
    }

    /// Return the list of withdrawals of this block.
    pub fn withdrawals(&self) -> Vec<Withdrawal> {
        let eth_withdrawals = self.eth_block.withdrawals.clone().unwrap();
        eth_withdrawals
            .iter()
            .map({
                |w| {
                    Withdrawal::new(
                        w.index.as_u64(),
                        w.validator_index.as_u64(),
                        w.address,
                        w.amount.as_u64(),
                    )
                    .unwrap()
                }
            })
            .collect_vec()
    }

    /// Return root of withdrawals of this block
    pub fn withdrawals_root(&self) -> H256 {
        self.eth_block.withdrawals_root.unwrap_or_default()
    }

    /// Push a copy event to the block.
    pub fn add_copy_event(&mut self, event: CopyEvent) {
        self.copy_events.push(event);
    }
    /// Push an exponentiation event to the block.
    pub fn add_exp_event(&mut self, event: ExpEvent) {
        self.exp_events.push(event);
    }
}
