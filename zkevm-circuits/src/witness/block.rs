use super::{ExecStep, Rw, RwMap, Transaction};
use crate::{
    evm_circuit::{detect_fixed_table_tags, EvmCircuit},
    exp_circuit::param::OFFSET_INCREMENT,
    instance::public_data_convert,
    table::BlockContextFieldTag,
    util::{log2_ceil, word::WordLoHi, SubCircuit},
};
use axiom_eth::storage::circuit::EthBlockStorageInput;
use bus_mapping::{
    circuit_input_builder::{self, CopyEvent, ExpEvent, FeatureConfig, FixedCParams, Withdrawal},
    state_db::CodeDB,
    Error,
};
use eth_types::{Address, Field, ToScalar, Word, H256};
use halo2_proofs::circuit::Value;
use itertools::Itertools;

// TODO: Remove fields that are duplicated in`eth_block`
/// Block is the struct used by all circuits, which contains all the needed
/// data for witness generation.
#[derive(Debug, Clone, Default)]
pub struct Block<F> {
    /// The randomness for random linear combination
    pub randomness: F,
    /// Transactions in the block
    pub txs: Vec<Transaction>,
    /// EndBlock step that is repeated after the last transaction and before
    /// reaching the last EVM row.
    pub end_block_not_last: ExecStep,
    /// Last EndBlock step that appears in the last EVM row.
    pub end_block_last: ExecStep,
    /// Read write events in the RwTable
    pub rws: RwMap,
    /// Bytecode used in the block
    pub bytecodes: CodeDB,
    /// The block context
    pub context: BlockContext,
    /// Copy events for the copy circuit's table.
    pub copy_events: Vec<CopyEvent>,
    /// Exponentiation traces for the exponentiation circuit's table.
    pub exp_events: Vec<ExpEvent>,
    /// Pad exponentiation circuit to make selectors fixed.
    pub exp_circuit_pad_to: usize,
    /// Circuit Setup Parameters
    pub circuits_params: FixedCParams,
    /// Feature Config
    pub feature_config: FeatureConfig,
    /// Inputs to the SHA3 opcode
    pub sha3_inputs: Vec<Vec<u8>>,
    /// State root of the previous block
    pub prev_state_root: Word, // TODO: Make this H256
    /// Keccak inputs
    pub keccak_inputs: Vec<Vec<u8>>,
    /// Original Block from geth
    pub eth_block: eth_types::Block<eth_types::Transaction>,
    /// Axiom Inputs
    pub axiom_inputs: EthBlockStorageInput,
}

impl<F: Field> Block<F> {
    /// For each tx, for each step, print the rwc at the beginning of the step,
    /// and all the rw operations of the step.
    #[allow(dead_code, reason = "useful debug function")]
    pub(crate) fn debug_print_txs_steps_rw_ops(&self) {
        for (tx_idx, tx) in self.txs.iter().enumerate() {
            println!("tx {}", tx_idx);
            for step in tx.steps() {
                println!("> Step {:?}", step.exec_state);
                for rw_idx in 0..step.bus_mapping_instance.len() {
                    let rw = self.get_rws(step, rw_idx);
                    let rw_str = if rw.is_write() { "WRIT" } else { "READ" };
                    println!("  {} {} {:?}", rw.rw_counter(), rw_str, rw);
                }
            }
        }
    }

    /// Get a read-write record
    pub(crate) fn get_rws(&self, step: &ExecStep, index: usize) -> Rw {
        self.rws[step.rw_index(index)]
    }

    /// Return the list of withdrawals of this block.
    pub fn withdrawals(&self) -> Vec<Withdrawal> {
        let eth_withdrawals = self.eth_block.withdrawals.clone().unwrap_or_default();
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

    /// Return the root of withdrawals in this block
    pub fn withdrawals_root(&self) -> H256 {
        self.eth_block.withdrawals_root.unwrap_or_default()
    }

    /// Obtains the expected Circuit degree needed in order to be able to test
    /// the EvmCircuit with this block without needing to configure the
    /// `ConstraintSystem`.
    pub fn get_test_degree(&self) -> u32 {
        let num_rows_required_for_execution_steps: usize =
            EvmCircuit::<F>::get_num_rows_required(self);
        let num_rows_required_for_rw_table: usize = self.circuits_params.max_rws;
        let num_rows_required_for_fixed_table: usize = detect_fixed_table_tags(self)
            .iter()
            .map(|tag| tag.build::<F>().count())
            .sum();
        let num_rows_required_for_bytecode_table =
            self.bytecodes.num_rows_required_for_bytecode_table();
        let num_rows_required_for_copy_table: usize =
            self.copy_events.iter().map(|c| c.bytes.len() * 2).sum();
        let num_rows_required_for_keccak_table: usize = self.keccak_inputs.len();
        let num_rows_required_for_tx_table: usize =
            self.txs.iter().map(|tx| 9 + tx.call_data.len()).sum();
        let num_rows_required_for_exp_table: usize = self
            .exp_events
            .iter()
            .map(|e| e.steps.len() * OFFSET_INCREMENT)
            .sum();

        let rows_needed: usize = itertools::max([
            num_rows_required_for_execution_steps,
            num_rows_required_for_rw_table,
            num_rows_required_for_fixed_table,
            num_rows_required_for_bytecode_table,
            num_rows_required_for_copy_table,
            num_rows_required_for_keccak_table,
            num_rows_required_for_tx_table,
            num_rows_required_for_exp_table,
            1 << 16, // u16 range lookup
        ])
        .unwrap();

        let k = log2_ceil(EvmCircuit::<F>::unusable_rows() + rows_needed);
        log::debug!(
            "num_rows_required_for rw_table={}, fixed_table={}, bytecode_table={}, \
            copy_table={}, keccak_table={}, tx_table={}, exp_table={}",
            num_rows_required_for_rw_table,
            num_rows_required_for_fixed_table,
            num_rows_required_for_bytecode_table,
            num_rows_required_for_copy_table,
            num_rows_required_for_keccak_table,
            num_rows_required_for_tx_table,
            num_rows_required_for_exp_table
        );
        log::debug!("evm circuit uses k = {}, rows = {}", k, rows_needed);
        k
    }
}

/// Block context for execution
#[derive(Debug, Default, Clone)]
pub struct BlockContext {
    /// The address of the miner for the block
    pub coinbase: Address,
    /// The gas limit of the block
    pub gas_limit: u64,
    /// The number of the block
    pub number: Word,
    /// The timestamp of the block
    pub timestamp: Word,
    /// The difficulty of the blcok
    pub difficulty: Word,
    /// The base fee, the minimum amount of gas fee for a transaction
    pub base_fee: Word,
    /// The hash of previous blocks
    pub history_hashes: Vec<Word>,
    /// The chain id
    pub chain_id: Word,
    /// The withdrawal root
    pub withdrawals_root: Word,
}

impl BlockContext {
    /// Assignments for block table
    pub fn table_assignments<F: Field>(&self) -> Vec<[Value<F>; 4]> {
        [
            vec![
                [
                    Value::known(F::from(BlockContextFieldTag::Coinbase as u64)),
                    Value::known(F::ZERO),
                    Value::known(WordLoHi::from(self.coinbase).lo()),
                    Value::known(WordLoHi::from(self.coinbase).hi()),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::Timestamp as u64)),
                    Value::known(F::ZERO),
                    Value::known(self.timestamp.to_scalar().unwrap()),
                    Value::known(F::ZERO),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::Number as u64)),
                    Value::known(F::ZERO),
                    Value::known(self.number.to_scalar().unwrap()),
                    Value::known(F::ZERO),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::Difficulty as u64)),
                    Value::known(F::ZERO),
                    Value::known(WordLoHi::from(self.difficulty).lo()),
                    Value::known(WordLoHi::from(self.difficulty).hi()),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::GasLimit as u64)),
                    Value::known(F::ZERO),
                    Value::known(F::from(self.gas_limit)),
                    Value::known(F::ZERO),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::BaseFee as u64)),
                    Value::known(F::ZERO),
                    Value::known(WordLoHi::from(self.base_fee).lo()),
                    Value::known(WordLoHi::from(self.base_fee).hi()),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::ChainId as u64)),
                    Value::known(F::ZERO),
                    Value::known(WordLoHi::from(self.chain_id).lo()),
                    Value::known(WordLoHi::from(self.chain_id).hi()),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::WithdrawalRoot as u64)),
                    Value::known(F::ZERO),
                    Value::known(WordLoHi::from(self.withdrawals_root).lo()),
                    Value::known(WordLoHi::from(self.withdrawals_root).hi()),
                ],
            ],
            {
                let len_history = self.history_hashes.len();
                self.history_hashes
                    .iter()
                    .enumerate()
                    .map(|(idx, hash)| {
                        [
                            Value::known(F::from(BlockContextFieldTag::BlockHash as u64)),
                            Value::known((self.number - len_history + idx).to_scalar().unwrap()),
                            Value::known(WordLoHi::from(*hash).lo()),
                            Value::known(WordLoHi::from(*hash).hi()),
                        ]
                    })
                    .collect()
            },
        ]
        .concat()
    }
}

impl From<&circuit_input_builder::Block> for BlockContext {
    fn from(block: &circuit_input_builder::Block) -> Self {
        Self {
            coinbase: block.coinbase,
            gas_limit: block.gas_limit,
            number: block.number,
            timestamp: block.timestamp,
            difficulty: block.difficulty,
            base_fee: block.base_fee,
            history_hashes: block.history_hashes.clone(),
            chain_id: block.chain_id,
            withdrawals_root: block.withdrawals_root().as_fixed_bytes().into(),
        }
    }
}

/// Convert a block struct in bus-mapping to a witness block used in circuits
pub fn block_convert<F: Field>(
    builder: &circuit_input_builder::CircuitInputBuilder<FixedCParams>,
) -> Result<Block<F>, Error> {
    let block = &builder.block;
    let code_db = &builder.code_db;
    let rws = RwMap::from(&block.container);
    rws.check_value();
    let mut block = Block {
        // randomness: F::from(0x100), // Special value to reveal elements after RLC
        randomness: F::from(0xcafeu64),
        context: block.into(),
        rws,
        txs: block.txs().to_vec(),
        end_block_not_last: block.block_steps.end_block_not_last.clone(),
        end_block_last: block.block_steps.end_block_last.clone(),
        bytecodes: code_db.clone(),
        copy_events: block.copy_events.clone(),
        exp_events: block.exp_events.clone(),
        sha3_inputs: block.sha3_inputs.clone(),
        circuits_params: builder.circuits_params,
        feature_config: builder.feature_config,
        exp_circuit_pad_to: <usize>::default(),
        prev_state_root: block.prev_state_root,
        keccak_inputs: circuit_input_builder::keccak_inputs(block, code_db)?,
        eth_block: block.eth_block.clone(),
        axiom_inputs: block.axiom_inputs.clone(),
    };
    let public_data = public_data_convert(&block);
    let rpi_bytes = public_data.get_pi_bytes(
        block.circuits_params.max_txs,
        block.circuits_params.max_withdrawals,
        block.circuits_params.max_calldata,
    );
    // PI Circuit
    block.keccak_inputs.extend_from_slice(&[rpi_bytes]);
    Ok(block)
}
