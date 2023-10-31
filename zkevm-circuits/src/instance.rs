//! The instance definition.

use eth_types::{geth_types::BlockConstants, BigEndianHash, Field, Keccak, U256};
use std::{iter, ops::Deref};

use eth_types::{geth_types::Transaction, Address, ToBigEndian, Word, H256};
use itertools::Itertools;

use crate::{util::word, witness::Block};

/// Values of the block table (as in the spec)
#[derive(Clone, Default, Debug)]
pub struct BlockValues {
    /// coinbase
    pub coinbase: Address,
    /// gas_limit
    pub gas_limit: u64,
    /// number
    pub number: u64,
    /// timestamp
    pub timestamp: u64,
    /// difficulty
    pub difficulty: Word,
    /// base_fee
    pub base_fee: Word, // NOTE: BaseFee was added by EIP-1559 and is ignored in legacy headers.
    /// chain_id
    pub chain_id: u64,
    /// history_hashes
    pub history_hashes: Vec<H256>,
    /// pox challenge bytecode hash
    pub pox_challenge_codehash: H256,
    /// pox exploit balance
    pub pox_exploit_balance: U256,
}

/// Extra values (not contained in block or tx tables)
#[derive(Default, Debug, Clone)]
pub struct ExtraValues {
    /// block_hash
    pub block_hash: H256,
    /// state_root
    pub state_root: H256,
    /// prev_state_root
    pub prev_state_root: H256,
}

/// PublicData contains all the values that the PiCircuit recieves as input
#[derive(Debug, Clone)]
pub struct PublicData {
    /// chain id
    pub chain_id: Word,
    /// History hashes contains the most recent 256 block hashes in history,
    /// where the latest one is at history_hashes[history_hashes.len() - 1].
    pub history_hashes: Vec<Word>,
    /// Block Transactions
    pub transactions: Vec<Transaction>,
    /// Block State Root
    pub state_root: H256,
    /// Previous block root
    pub prev_state_root: H256,
    /// Constants related to Ethereum block
    pub block_constants: BlockConstants,
    /// Block Hash
    pub block_hash: Option<H256>,
    /// POX Challenge Bytecode Hash
    pub pox_challenge_codehash: H256,
    /// POX Exploit Balance
    pub pox_exploit_balance: U256,
}

impl Default for PublicData {
    fn default() -> Self {
        PublicData {
            chain_id: Word::default(),
            history_hashes: vec![],
            transactions: vec![],
            state_root: H256::zero(),
            prev_state_root: H256::zero(),
            block_constants: BlockConstants::default(),
            block_hash: None,
            pox_challenge_codehash: H256::zero(),
            pox_exploit_balance: U256::zero(),
        }
    }
}

impl PublicData {
    /// Returns struct with values for the block table
    pub fn get_block_table_values(&self) -> BlockValues {
        let history_hashes = [
            vec![H256::zero(); 256 - self.history_hashes.len()],
            self.history_hashes
                .iter()
                .map(|&hash| H256::from(hash.to_be_bytes()))
                .collect(),
        ]
        .concat();
        BlockValues {
            coinbase: self.block_constants.coinbase,
            gas_limit: self.block_constants.gas_limit.as_u64(),
            number: self.block_constants.number.as_u64(),
            timestamp: self.block_constants.timestamp.as_u64(),
            difficulty: self.block_constants.difficulty,
            base_fee: self.block_constants.base_fee,
            chain_id: self.chain_id.as_u64(),
            history_hashes,
            pox_challenge_codehash: self.pox_challenge_codehash,
            pox_exploit_balance: self.pox_exploit_balance,
        }
    }

    /// Returns struct with the extra values
    pub fn get_extra_values(&self) -> ExtraValues {
        ExtraValues {
            block_hash: self.block_hash.unwrap_or_else(H256::zero),
            state_root: self.state_root,
            prev_state_root: self.prev_state_root,
        }
    }

    /// get the serialized public data bytes
    pub fn get_pi_bytes(&self) -> Vec<u8> {
        // Assign block table
        let block_values = self.get_block_table_values();
        let result = iter::empty()
            .chain(0u8.to_be_bytes()) // zero byte
            .chain(block_values.coinbase.to_fixed_bytes()) // coinbase
            .chain(block_values.gas_limit.to_be_bytes()) // gas_limit
            .chain(block_values.number.to_be_bytes()) // number
            .chain(block_values.timestamp.to_be_bytes()) // timestamp
            .chain(block_values.difficulty.to_be_bytes()) // difficulty
            .chain(block_values.base_fee.to_be_bytes()) // base_fee
            .chain(block_values.chain_id.to_be_bytes()) // chain_id
            .chain(
                block_values
                    .history_hashes
                    .iter()
                    .flat_map(|prev_hash| prev_hash.to_fixed_bytes()),
            ) // history_hashes
            .chain(block_values.pox_challenge_codehash.to_fixed_bytes()) // pox challenge bytecode hash
            .chain(block_values.pox_exploit_balance.to_be_bytes()); // pox exploit balance

        // Assign extra fields
        let extra_vals = self.get_extra_values();
        result
            .chain(extra_vals.block_hash.to_fixed_bytes()) // block hash
            .chain(extra_vals.state_root.to_fixed_bytes()) // block state root
            .chain(extra_vals.prev_state_root.to_fixed_bytes())
            .collect_vec() // previous block state root
    }

    /// generate public data from validator perspective
    pub fn get_rpi_digest_word<F: Field>(&self) -> word::Word<F> {
        let mut keccak = Keccak::default();
        keccak.update(&self.get_pi_bytes());
        let digest = keccak.digest();
        word::Word::from(Word::from_big_endian(&digest))
    }
}

/// convert witness block to public data
pub fn public_data_convert<F: Field>(block: &Block<F>) -> PublicData {
    PublicData {
        chain_id: block.context.chain_id,
        history_hashes: block.context.history_hashes.clone(),
        transactions: block.txs.iter().map(|tx| tx.deref().clone()).collect_vec(),
        state_root: block.eth_block.state_root,
        prev_state_root: H256::from_uint(&block.prev_state_root),
        block_hash: block.eth_block.hash,
        block_constants: BlockConstants {
            coinbase: block.context.coinbase,
            timestamp: block.context.timestamp,
            number: block.context.number.as_u64().into(),
            difficulty: block.context.difficulty,
            gas_limit: block.context.gas_limit.into(),
            base_fee: block.context.base_fee,
        },
        pox_challenge_codehash: H256::from_uint(&block.pox_challenge_codehash),
        pox_exploit_balance: block.pox_exploit_balance,
    }
}
