//! The Super Circuit is a circuit that contains all the circuits of the
//! zkEVM in order to achieve two things:
//! - Check the correct integration between circuits via the shared lookup tables, to verify that
//!   the table layouts match.
//! - Allow having a single circuit setup for which a proof can be generated that would be verified
//!   under a single aggregation circuit for the first milestone.
//!
//! The current implementation contains the following circuits:
//!
//! - [x] EVM Circuit
//! - [ ] State Circuit
//! - [x] Tx Circuit
//! - [x] Bytecode Circuit
//! - [x] Copy Circuit
//! - [x] Exponentiation Circuit
//! - [ ] Keccak Circuit
//! - [ ] MPT Circuit
//! - [x] PublicInputs Circuit
//!
//! And the following shared tables, with the circuits that use them:
//!
//! - [x] Copy Table
//!   - [x] Copy Circuit
//!   - [x] EVM Circuit
//! - [x] Exponentiation Table
//!   - [x] EVM Circuit
//! - [ ] Rw Table
//!   - [ ] State Circuit
//!   - [ ] EVM Circuit
//!   - [ ] Copy Circuit
//! - [x] Tx Table
//!   - [x] Tx Circuit
//!   - [x] EVM Circuit
//!   - [x] Copy Circuit
//!   - [x] PublicInputs Circuit
//! - [x] Bytecode Table
//!   - [x] Bytecode Circuit
//!   - [x] EVM Circuit
//!   - [x] Copy Circuit
//! - [ ] Block Table
//!   - [ ] EVM Circuit
//!   - [x] PublicInputs Circuit
//! - [ ] MPT Table
//!   - [ ] MPT Circuit
//!   - [ ] State Circuit
//! - [x] Keccak Table
//!   - [ ] Keccak Circuit
//!   - [ ] EVM Circuit
//!   - [x] Bytecode Circuit
//!   - [x] Tx Circuit
//!   - [ ] MPT Circuit
pub(crate) mod precompile_block_trace;
/// #[cfg(any(feature = "test", test))]
pub mod test;

#[cfg(feature = "poseidon-codehash")]
use crate::bytecode_circuit::circuit::to_poseidon_hash::{
    ToHashBlockBytecodeCircuitConfigArgs, ToHashBlockCircuitConfig, HASHBLOCK_BYTES_IN_FIELD,
};
#[cfg(not(feature = "poseidon-codehash"))]
use crate::bytecode_circuit::circuit::BytecodeCircuitConfig;
use crate::{
    bytecode_circuit::circuit::{BytecodeCircuit, BytecodeCircuitConfigArgs},
    copy_circuit::{CopyCircuit, CopyCircuitConfig, CopyCircuitConfigArgs},
    // ecc_circuit::{EccCircuit, EccCircuitConfig, EccCircuitConfigArgs},
    evm_circuit::{EvmCircuit, EvmCircuitConfig, EvmCircuitConfigArgs},
    exp_circuit::{ExpCircuit, ExpCircuitArgs, ExpCircuitConfig},
    keccak_circuit::{
        keccak_packed_multi::get_num_rows_per_round, KeccakCircuit, KeccakCircuitConfig,
        KeccakCircuitConfigArgs,
    },
    modexp_circuit::{ModExpCircuit, ModExpCircuitConfig},
    pi_circuit::{PiCircuit, PiCircuitConfig, PiCircuitConfigArgs},
    // poseidon_circuit::{PoseidonCircuit, PoseidonCircuitConfig, PoseidonCircuitConfigArgs},
    rlp_circuit_fsm::{RlpCircuit, RlpCircuitConfig, RlpCircuitConfigArgs},
    sha256_circuit::{
        CircuitConfig as SHA256CircuitConfig, CircuitConfigArgs as SHA256CircuitConfigArgs,
        SHA256Circuit,
    },
    // sig_circuit::{SigCircuit, SigCircuitConfig, SigCircuitConfigArgs},
    state_circuit::{StateCircuit, StateCircuitConfig, StateCircuitConfigArgs},
    table::{
        BlockTable, BytecodeTable, CopyTable, EccTable, ExpTable, KeccakTable, ModExpTable,
        MptTable, PoseidonTable, PowOfRandTable, RlpFsmRlpTable as RlpTable, RwTable, SHA256Table,
        SigTable, TxTable, U16Table, U8Table,
    },
    tx_circuit::{TxCircuit, TxCircuitConfig, TxCircuitConfigArgs},
    util::{circuit_stats, log2_ceil, Challenges, SubCircuit, SubCircuitConfig},
    witness::{block_convert, Block, Transaction},
};

#[cfg(feature = "zktrie")]
use crate::mpt_circuit::{MptCircuit, MptCircuitConfig, MptCircuitConfigArgs};

use bus_mapping::{
    circuit_input_builder::{CircuitInputBuilder, CircuitsParams},
    mock::BlockData,
};
use eth_types::{geth_types::GethData, Field};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem, Error},
};
use itertools::Itertools;
// use snark_verifier_sdk::CircuitExt;

/// Configuration of the Super Circuit
#[derive(Clone)]
pub struct SuperCircuitConfig<F: Field> {
    block_table: BlockTable,
    // mpt_table: MptTable,
    rlp_table: RlpTable,
    tx_table: TxTable,
    poseidon_table: PoseidonTable,
    u8_table: U8Table,
    u16_table: U16Table,
    evm_circuit: EvmCircuitConfig<F>,
    state_circuit: StateCircuitConfig<F>,
    tx_circuit: TxCircuitConfig<F>,
    // sig_circuit: SigCircuitConfig<F>,
    modexp_circuit: ModExpCircuitConfig,
    // ecc_circuit: EccCircuitConfig<F>,
    sha256_circuit: SHA256CircuitConfig,
    #[cfg(not(feature = "poseidon-codehash"))]
    bytecode_circuit: BytecodeCircuitConfig<F>,
    #[cfg(feature = "poseidon-codehash")]
    bytecode_circuit: ToHashBlockCircuitConfig<F, HASHBLOCK_BYTES_IN_FIELD>,
    copy_circuit: CopyCircuitConfig<F>,
    keccak_circuit: KeccakCircuitConfig<F>,
    // poseidon_circuit: PoseidonCircuitConfig<F>,
    pi_circuit: PiCircuitConfig<F>,
    exp_circuit: ExpCircuitConfig<F>,
    rlp_circuit: RlpCircuitConfig<F>,
    // /// Mpt Circuit
    // #[cfg(feature = "zktrie")]
    // mpt_circuit: MptCircuitConfig<F>,
}

/// Circuit configuration arguments
pub struct SuperCircuitConfigArgs {
    /// Max txs
    pub max_txs: usize,
    /// Max calldata
    pub max_calldata: usize,
    /// Max inner blocks
    pub max_inner_blocks: usize,
    /// Mock randomness
    pub mock_randomness: u64,
    /// Challenges
    pub challenges: crate::util::Challenges,
}

impl SubCircuitConfig<Fr> for SuperCircuitConfig<Fr> {
    type ConfigArgs = SuperCircuitConfigArgs;

    /// Configure SuperCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<Fr>,
        Self::ConfigArgs {
            max_txs: _,
            max_calldata: _,
            max_inner_blocks: _,
            mock_randomness: _mock_randomness,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let log_circuit_info = |meta: &ConstraintSystem<Fr>, tag: &str| {
            log::debug!("circuit info after {}: {:#?}", tag, circuit_stats(meta));
        };
        let challenges_expr = challenges.exprs(meta);

        let tx_table = TxTable::construct(meta);
        log_circuit_info(meta, "tx table");
        let rw_table = RwTable::construct(meta);
        log_circuit_info(meta, "rw table");

        // let mpt_table = MptTable::construct(meta);
        log_circuit_info(meta, "mpt table");
        let poseidon_table = PoseidonTable::construct(meta);
        log_circuit_info(meta, "poseidon table");

        let bytecode_table = BytecodeTable::construct(meta);
        log_circuit_info(meta, "bytecode table");
        let block_table = BlockTable::construct(meta);
        log_circuit_info(meta, "block table");
        let q_copy_table = meta.fixed_column();
        log::debug!("q_copy_table {:?}", q_copy_table);
        let copy_table = CopyTable::construct(meta, q_copy_table);
        log_circuit_info(meta, "copy table");
        let exp_table = ExpTable::construct(meta);
        log_circuit_info(meta, "exp table");
        let rlp_table = RlpTable::construct(meta);
        log_circuit_info(meta, "rlp table");
        let keccak_table = KeccakTable::construct(meta);
        log_circuit_info(meta, "keccak table");
        let sha256_table = SHA256Table::construct(meta);
        log_circuit_info(meta, "sha256 table");
        let sig_table = SigTable::construct(meta);
        log_circuit_info(meta, "sig table");
        let modexp_table = ModExpTable::construct(meta);
        log_circuit_info(meta, "modexp table");
        let ecc_table = EccTable::construct(meta);
        log_circuit_info(meta, "ecc table");
        let pow_of_rand_table = PowOfRandTable::construct(meta, &challenges_expr);
        log_circuit_info(meta, "power of randomness table");

        let u8_table = U8Table::construct(meta);
        log_circuit_info(meta, "u8 table");
        let u16_table = U16Table::construct(meta);
        log_circuit_info(meta, "u16 table");

        assert!(get_num_rows_per_round() == 12);
        let keccak_circuit = KeccakCircuitConfig::new(
            meta,
            KeccakCircuitConfigArgs {
                keccak_table: keccak_table.clone(),
                challenges: challenges_expr.clone(),
            },
        );
        log_circuit_info(meta, "keccak circuit");

        let sha256_circuit = SHA256CircuitConfig::new(
            meta,
            SHA256CircuitConfigArgs {
                sha256_table: sha256_table.clone(),
                challenges: challenges_expr.clone(),
            },
        );
        log_circuit_info(meta, "sha256 circuit");

        // let poseidon_circuit =
        //     PoseidonCircuitConfig::new(meta, PoseidonCircuitConfigArgs { poseidon_table });
        // log_circuit_info(meta, "poseidon circuit");

        let rlp_circuit = RlpCircuitConfig::new(
            meta,
            RlpCircuitConfigArgs {
                rlp_table,
                u8_table,
                challenges: challenges_expr.clone(),
            },
        );
        log_circuit_info(meta, "rlp circuit");

        let pi_circuit = PiCircuitConfig::new(
            meta,
            PiCircuitConfigArgs {
                block_table: block_table.clone(),
                keccak_table: keccak_table.clone(),
                tx_table: tx_table.clone(),
                challenges: challenges_expr.clone(),
            },
        );
        log_circuit_info(meta, "pi circuit");

        let tx_circuit = TxCircuitConfig::new(
            meta,
            TxCircuitConfigArgs {
                block_table: block_table.clone(),
                tx_table: tx_table.clone(),
                keccak_table: keccak_table.clone(),
                rlp_table,
                sig_table,
                u8_table,
                u16_table,
                challenges: challenges_expr.clone(),
            },
        );
        log_circuit_info(meta, "tx circuit");

        #[cfg(not(feature = "poseidon-codehash"))]
        let bytecode_circuit = BytecodeCircuitConfig::new(
            meta,
            BytecodeCircuitConfigArgs {
                bytecode_table: bytecode_table.clone(),
                keccak_table: keccak_table.clone(),
                challenges: challenges_expr.clone(),
            },
        );
        #[cfg(feature = "poseidon-codehash")]
        let bytecode_circuit = ToHashBlockCircuitConfig::new(
            meta,
            ToHashBlockBytecodeCircuitConfigArgs {
                base_args: BytecodeCircuitConfigArgs {
                    bytecode_table: bytecode_table.clone(),
                    keccak_table: keccak_table.clone(),
                    challenges: challenges_expr.clone(),
                },
                poseidon_table,
            },
        );

        log_circuit_info(meta, "bytecode circuit");

        let copy_circuit = CopyCircuitConfig::new(
            meta,
            CopyCircuitConfigArgs {
                tx_table: tx_table.clone(),
                rw_table,
                bytecode_table: bytecode_table.clone(),
                copy_table,
                q_enable: q_copy_table,
                challenges: challenges_expr.clone(),
            },
        );
        log_circuit_info(meta, "copy circuit");

        // #[cfg(feature = "zktrie")]
        // let mpt_circuit = MptCircuitConfig::new(
        //     meta,
        //     MptCircuitConfigArgs {
        //         poseidon_table,
        //         mpt_table,
        //         challenges,
        //     },
        // );
        // #[cfg(feature = "zktrie")]
        // log_circuit_info(meta, "zktrie circuit");

        let modexp_circuit = ModExpCircuitConfig::new(meta, modexp_table);
        log_circuit_info(meta, "modexp circuit");
        let state_circuit = StateCircuitConfig::new(
            meta,
            StateCircuitConfigArgs {
                rw_table,
                // mpt_table,
                challenges: challenges_expr.clone(),
            },
        );
        log_circuit_info(meta, "state circuit");

        let exp_circuit = ExpCircuitConfig::new(
            meta,
            ExpCircuitArgs {
                exp_table,
                u16_table,
            },
        );
        log_circuit_info(meta, "exp circuit");

        let evm_circuit = EvmCircuitConfig::new(
            meta,
            EvmCircuitConfigArgs {
                challenges: challenges_expr.clone(),
                tx_table: tx_table.clone(),
                rw_table,
                bytecode_table,
                block_table: block_table.clone(),
                copy_table,
                keccak_table: keccak_table.clone(),
                sha256_table,
                exp_table,
                sig_table,
                modexp_table,
                ecc_table,
                pow_of_rand_table,
            },
        );
        log_circuit_info(meta, "evm circuit");

        // Sig Circuit and ECC Circuit use halo2-lib's vertifcal assignments gates
        // and need to be configured after Circuits with higher counts of unique rotation queries
        // (ex. Keccak, EVM) to avoid assigning advice values into blinding area.
        // let sig_circuit = SigCircuitConfig::new(
        //     meta,
        //     SigCircuitConfigArgs {
        //         keccak_table,
        //         sig_table,
        //         challenges: challenges_expr.clone(),
        //     },
        // );
        // log_circuit_info(meta, "sig circuit");

        // let ecc_circuit = EccCircuitConfig::new(
        //     meta,
        //     EccCircuitConfigArgs {
        //         ecc_table,
        //         challenges: challenges_expr,
        //     },
        // );
        // log_circuit_info(meta, "ecc circuit");

        #[cfg(feature = "onephase")]
        if meta.max_phase() != 0 {
            log::warn!("max_phase: {}", meta.max_phase());
        }

        SuperCircuitConfig {
            block_table,
            // mpt_table,
            tx_table,
            rlp_table,
            poseidon_table,
            u8_table,
            u16_table,
            evm_circuit,
            state_circuit,
            copy_circuit,
            bytecode_circuit,
            keccak_circuit,
            sha256_circuit,
            // poseidon_circuit,
            pi_circuit,
            rlp_circuit,
            tx_circuit,
            exp_circuit,
            // sig_circuit,
            modexp_circuit,
            // ecc_circuit,
            // #[cfg(feature = "zktrie")]
            // mpt_circuit,
        }
    }
}

/// Row usage for each sub circuit
#[derive(Clone, Default, Debug)]
pub struct SubcircuitRowUsage {
    /// Subcircuit name
    pub name: String,
    // TODO: better name?
    /// Without padding
    pub row_num_real: usize,
    /// With padding
    pub row_num_total: usize,
}

/// The Super Circuit contains all the zkEVM circuits
#[derive(Clone, Debug)]
pub struct SuperCircuit<
    F: Field,
    const MAX_TXS: usize,
    const MAX_CALLDATA: usize,
    const MAX_INNER_BLOCKS: usize,
    const MOCK_RANDOMNESS: u64,
> {
    /// EVM Circuit
    pub evm_circuit: EvmCircuit<F>,
    /// State Circuit
    pub state_circuit: StateCircuit<F>,
    /// The transaction circuit that will be used in the `synthesize` step.
    pub tx_circuit: TxCircuit<F>,
    /// Public Input Circuit
    pub pi_circuit: PiCircuit<F>,
    /// Bytecode Circuit
    pub bytecode_circuit: BytecodeCircuit<F>,
    /// Copy Circuit
    pub copy_circuit: CopyCircuit<F>,
    /// Exp Circuit
    pub exp_circuit: ExpCircuit<F>,
    /// Keccak Circuit
    pub keccak_circuit: KeccakCircuit<F>,
    /// SHA256 Circuit
    pub sha256_circuit: SHA256Circuit<F>,
    /// Poseidon hash Circuit
    // pub poseidon_circuit: PoseidonCircuit<F>,
    /// Sig Circuit
    // pub sig_circuit: SigCircuit<F>,
    /// Modexp Circuit
    pub modexp_circuit: ModExpCircuit<F>,
    /// Ecc Circuit
    // pub ecc_circuit: EccCircuit<F, 9>,
    /// Rlp Circuit
    pub rlp_circuit: RlpCircuit<F, Transaction>,
    /// Mpt Circuit
    #[cfg(feature = "zktrie")]
    pub mpt_circuit: MptCircuit<F>,

    circuit_params: CircuitsParams,
}

impl<
        F: Field,
        const MAX_TXS: usize,
        const MAX_CALLDATA: usize,
        const MAX_INNER_BLOCKS: usize,
        const MOCK_RANDOMNESS: u64,
    > SuperCircuit<F, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, MOCK_RANDOMNESS>
{
    /// Return the number of rows required to verify a given block
    pub fn get_num_rows_required(block: &Block<Fr>) -> usize {
        let num_rows_evm_circuit = EvmCircuit::<Fr>::get_num_rows_required(block);
        assert_eq!(block.circuits_params.max_txs, MAX_TXS);
        // FIXME: need to call the SigCircuit::get_num_rows_required instead
        // let num_rows_tx_circuit =
        //     TxCircuitConfig::<F>::get_num_rows_required(block.circuits_params.max_txs);
        // num_rows_evm_circuit.max(num_rows_tx_circuit)
        num_rows_evm_circuit
    }
    /// Return the minimum number of rows required to prove the block
    pub fn min_num_rows_block_subcircuits(block: &Block<Fr>) -> Vec<SubcircuitRowUsage> {
        log::debug!("start min_num_rows_block_subcircuits");
        let mut rows = Vec::new();
        let mut push = |name, usage| {
            log::debug!("{name} circuit row: {usage:?}");
            rows.push((name, usage));
        };
        let evm = EvmCircuit::min_num_rows_block(block);
        push("evm", evm);
        let state = StateCircuit::min_num_rows_block(block);
        push("state", state);
        let bytecode = BytecodeCircuit::min_num_rows_block(block);
        push("bytecode", bytecode);
        let copy = CopyCircuit::min_num_rows_block(block);
        push("copy", copy);
        let keccak = KeccakCircuit::min_num_rows_block(block);
        push("keccak", keccak);
        let sha256 = SHA256Circuit::min_num_rows_block(block);
        push("sha256", sha256);
        let tx = TxCircuit::min_num_rows_block(block);
        push("tx", tx);
        let rlp = RlpCircuit::min_num_rows_block(block);
        push("rlp", rlp);
        let exp = ExpCircuit::min_num_rows_block(block);
        push("exp", exp);
        let mod_exp = ModExpCircuit::min_num_rows_block(block);
        push("mod_exp", mod_exp);
        let pi = PiCircuit::min_num_rows_block(block);
        push("pi", pi);
        // let poseidon = PoseidonCircuit::min_num_rows_block(block);
        // push("poseidon", poseidon);
        // let sig = SigCircuit::min_num_rows_block(block);
        // push("sig", sig);
        // let ecc = EccCircuit::<Fr, 9>::min_num_rows_block(block);
        // push("ecc", ecc);
        #[cfg(feature = "zktrie")]
        {
            let mpt = MptCircuit::<Fr>::min_num_rows_block(block);
            push("mpt", mpt);
        }

        let row_usage_details = rows
            .into_iter()
            .map(|(name, (row_num_real, row_num_total))| SubcircuitRowUsage {
                name: name.to_string(),
                row_num_real,
                row_num_total,
            })
            .collect_vec();
        {
            let mut row_usage_details_sorted = row_usage_details.clone();
            row_usage_details_sorted.sort_by_key(|r| r.row_num_real);
            row_usage_details_sorted.reverse();
            for detail in &row_usage_details_sorted {
                log::debug!("row detail {} {}", detail.name, detail.row_num_real);
            }
        }
        row_usage_details
    }
}

// Eventhough the SuperCircuit is not a subcircuit we implement the SubCircuit
// trait for it in order to get the `new_from_block` and `instance` methods that
// allow us to generalize integration tests.
impl<
        const MAX_TXS: usize,
        const MAX_CALLDATA: usize,
        const MAX_INNER_BLOCKS: usize,
        const MOCK_RANDOMNESS: u64,
    > SubCircuit<Fr>
    for SuperCircuit<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, MOCK_RANDOMNESS>
{
    type Config = SuperCircuitConfig<Fr>;

    fn unusable_rows() -> usize {
        itertools::max([
            EvmCircuit::<Fr>::unusable_rows(),
            StateCircuit::<Fr>::unusable_rows(),
            TxCircuit::<Fr>::unusable_rows(),
            // TODO: The PiCircuit unusable_rows fn is not implemented
            // and returns the arbitrary default number, causing overflow
            // PiCircuit::<Fr>::unusable_rows(),
            BytecodeCircuit::<Fr>::unusable_rows(),
            CopyCircuit::<Fr>::unusable_rows(),
            ExpCircuit::<Fr>::unusable_rows(),
            KeccakCircuit::<Fr>::unusable_rows(),
        ])
        .unwrap()
    }

    fn new_from_block(block: &Block<Fr>) -> Self {
        let evm_circuit = EvmCircuit::new_from_block(block);
        let state_circuit = StateCircuit::new_from_block(block);
        let tx_circuit = TxCircuit::new_from_block(block);
        let pi_circuit = PiCircuit::new_from_block(block);
        let bytecode_circuit = BytecodeCircuit::new_from_block(block);
        let copy_circuit = CopyCircuit::new_from_block_no_external(block);
        let exp_circuit = ExpCircuit::new_from_block(block);
        let modexp_circuit = ModExpCircuit::new_from_block(block);
        let keccak_circuit = KeccakCircuit::new_from_block(block);
        let sha256_circuit = SHA256Circuit::new_from_block(block);
        // let poseidon_circuit = PoseidonCircuit::new_from_block(block);
        let rlp_circuit = RlpCircuit::new_from_block(block);
        // let sig_circuit = SigCircuit::new_from_block(block);
        // let ecc_circuit = EccCircuit::new_from_block(block);
        #[cfg(feature = "zktrie")]
        let mpt_circuit = MptCircuit::new_from_block(block);
        SuperCircuit::<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, MOCK_RANDOMNESS> {
            evm_circuit,
            state_circuit,
            tx_circuit,
            pi_circuit,
            bytecode_circuit,
            copy_circuit,
            exp_circuit,
            keccak_circuit,
            sha256_circuit,
            // poseidon_circuit,
            rlp_circuit,
            // sig_circuit,
            modexp_circuit,
            // ecc_circuit,
            #[cfg(feature = "zktrie")]
            mpt_circuit,
            circuit_params: block.circuits_params,
        }
    }

    /// Returns suitable inputs for the SuperCircuit.
    fn instance(&self) -> Vec<Vec<Fr>> {
        let mut instance = Vec::new();
        instance.extend_from_slice(&self.keccak_circuit.instance());
        instance.extend_from_slice(&self.pi_circuit.instance());
        instance.extend_from_slice(&self.tx_circuit.instance());
        instance.extend_from_slice(&self.bytecode_circuit.instance());
        instance.extend_from_slice(&self.copy_circuit.instance());
        instance.extend_from_slice(&self.state_circuit.instance());
        instance.extend_from_slice(&self.exp_circuit.instance());
        instance.extend_from_slice(&self.evm_circuit.instance());

        instance
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &Block<Fr>) -> (usize, usize) {
        let row_usage = Self::min_num_rows_block_subcircuits(block);
        (
            itertools::max(row_usage.iter().map(|x| x.row_num_real)).unwrap(),
            itertools::max(row_usage.iter().map(|x| x.row_num_total)).unwrap(),
        )
    }

    /// Make the assignments to the SuperCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &crate::util::Challenges<Value<Fr>>,
        layouter: &mut impl Layouter<Fr>,
    ) -> Result<(), Error> {
        log::debug!("assigning evm_circuit");
        self.evm_circuit
            .synthesize_sub(&config.evm_circuit, challenges, layouter)?;

        if !challenges.lookup_input().is_none() {
            let is_mock_prover = format!("{:?}", challenges.lookup_input()) == *"Value { inner: Some(0x207a52ba34e1ed068be1e33b0bc39c8ede030835f549fe5c0dbe91dce97d17d2) }";
            if is_mock_prover {
                log::info!("continue assignment only for 3rd phase");
            } else {
                log::info!("only evm circuit needs 3rd phase assignment");
                return Ok(());
            }
        }
        log::debug!("assigning keccak_circuit");
        self.keccak_circuit
            .synthesize_sub(&config.keccak_circuit, challenges, layouter)?;
        log::debug!("assigning sha256_circuit");
        self.sha256_circuit
            .synthesize_sub(&config.sha256_circuit, challenges, layouter)?;
        log::debug!("assigning poseidon_circuit");
        // self.poseidon_circuit
        //     .synthesize_sub(&config.poseidon_circuit, challenges, layouter)?;
        log::debug!("assigning bytecode_circuit");
        self.bytecode_circuit
            .synthesize_sub(&config.bytecode_circuit, challenges, layouter)?;
        log::debug!("assigning tx_circuit");
        self.tx_circuit
            .synthesize_sub(&config.tx_circuit, challenges, layouter)?;
        // log::debug!("assigning sig_circuit");
        // self.sig_circuit
        //     .synthesize_sub(&config.sig_circuit, challenges, layouter)?;
        // log::debug!("assigning ecc_circuit");
        // self.ecc_circuit
        //     .synthesize_sub(&config.ecc_circuit, challenges, layouter)?;
        log::debug!("assigning modexp_circuit");
        self.modexp_circuit
            .synthesize_sub(&config.modexp_circuit, challenges, layouter)?;
        log::debug!("assigning state_circuit");
        self.state_circuit
            .synthesize_sub(&config.state_circuit, challenges, layouter)?;
        log::debug!("assigning copy_circuit");
        self.copy_circuit
            .synthesize_sub(&config.copy_circuit, challenges, layouter)?;
        log::debug!("assigning exp_circuit");
        self.exp_circuit
            .synthesize_sub(&config.exp_circuit, challenges, layouter)?;

        log::debug!("assigning pi_circuit");
        self.pi_circuit
            .import_tx_values(self.tx_circuit.value_cells.borrow().clone().unwrap());
        self.pi_circuit
            .synthesize_sub(&config.pi_circuit, challenges, layouter)?;
        self.pi_circuit.connect_export(
            layouter,
            self.state_circuit.exports.borrow().as_ref(),
            self.evm_circuit.exports.borrow().as_ref(),
        )?;

        log::debug!("assigning rlp_circuit");
        self.rlp_circuit
            .synthesize_sub(&config.rlp_circuit, challenges, layouter)?;

        // load both poseidon table and zktrie table
        // #[cfg(feature = "zktrie")]
        // {
        //     log::debug!("assigning mpt_circuit");
        //     self.mpt_circuit
        //         .synthesize_sub(&config.mpt_circuit, challenges, layouter)?;
        // }

        log::debug!("super circuit synthesize_sub done");
        Ok(())
    }
}

impl<
        const MAX_TXS: usize,
        const MAX_CALLDATA: usize,
        const MAX_INNER_BLOCKS: usize,
        const MOCK_RANDOMNESS: u64,
    > Circuit<Fr> for SuperCircuit<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, MOCK_RANDOMNESS>
{
    type Config = (SuperCircuitConfig<Fr>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        let dummy_block = Block::<Fr> {
            circuits_params: self.circuit_params,
            ..Default::default()
        };
        Self::new_from_block(&dummy_block)
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let challenges = Challenges::construct(meta);
        (
            SuperCircuitConfig::new(
                meta,
                SuperCircuitConfigArgs {
                    max_txs: MAX_TXS,
                    max_calldata: MAX_CALLDATA,
                    max_inner_blocks: MAX_INNER_BLOCKS,
                    mock_randomness: MOCK_RANDOMNESS,
                    challenges,
                },
            ),
            challenges,
        )
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&layouter);

        config.u8_table.load(&mut layouter)?;
        config.u16_table.load(&mut layouter)?;

        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

impl<
        const MAX_TXS: usize,
        const MAX_CALLDATA: usize,
        const MAX_INNER_BLOCKS: usize,
        const MOCK_RANDOMNESS: u64,
    > SuperCircuit<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, MOCK_RANDOMNESS>
{
    /// doc
    pub fn synthesize_2(
        &self,
        (config, challenges): <SuperCircuit<
            Fr,
            MAX_TXS,
            MAX_CALLDATA,
            MAX_INNER_BLOCKS,
            MOCK_RANDOMNESS,
        > as halo2_proofs::plonk::Circuit<Fr>>::Config,
        layouter: &mut impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(layouter);

        config.u8_table.load(layouter)?;
        config.u16_table.load(layouter)?;

        self.synthesize_sub(&config, &challenges, layouter)
    }
}

// impl<
//         const MAX_TXS: usize,
//         const MAX_CALLDATA: usize,
//         const MAX_INNER_BLOCKS: usize,
//         const MOCK_RANDOMNESS: u64,
//     > CircuitExt<F>
//     for SuperCircuit<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, MOCK_RANDOMNESS>
// {
//     fn num_instance(&self) -> Vec<usize> {
//         self.instances().iter().map(|l| l.len()).collect_vec()
//     }

//     fn instances(&self) -> Vec<Vec<F>> {
//         self.instance()
//     }
// }

impl<
        const MAX_TXS: usize,
        const MAX_CALLDATA: usize,
        const MAX_INNER_BLOCKS: usize,
        const MOCK_RANDOMNESS: u64,
    > SuperCircuit<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, MOCK_RANDOMNESS>
{
    /// From the witness data, generate a SuperCircuit instance with all of the
    /// sub-circuits filled with their corresponding witnesses.
    ///
    /// Also, return with it the minimum required SRS degree for the
    /// circuit and the Public Inputs needed.
    #[allow(clippy::type_complexity)]
    pub fn build(
        geth_data: GethData,
        circuits_params: CircuitsParams,
    ) -> Result<(u32, Self, Vec<Vec<Fr>>, CircuitInputBuilder), bus_mapping::Error> {
        let block_data =
            BlockData::new_from_geth_data_with_params(geth_data.clone(), circuits_params);

        let mut builder = block_data.new_circuit_input_builder();
        builder
            .handle_block(&geth_data.eth_block, &geth_data.geth_traces)
            .expect("could not handle block tx");

        let ret = Self::build_from_circuit_input_builder(&builder)?;
        Ok((ret.0, ret.1, ret.2, builder))
    }

    /// From CircuitInputBuilder, generate a SuperCircuit instance with all of
    /// the sub-circuits filled with their corresponding witnesses.
    ///
    /// Also, return with it the minimum required SRS degree for the circuit and
    /// the Public Inputs needed.
    pub fn build_from_circuit_input_builder(
        builder: &CircuitInputBuilder,
    ) -> Result<(u32, Self, Vec<Vec<Fr>>), bus_mapping::Error> {
        let block = block_convert(&builder.block, &builder.code_db).unwrap();
        assert_eq!(block.circuits_params.max_txs, MAX_TXS);
        assert_eq!(block.circuits_params.max_calldata, MAX_CALLDATA);
        Self::build_from_witness_block(block)
    }
    /// ..
    pub fn build_from_witness_block(
        block: Block<Fr>,
    ) -> Result<(u32, Self, Vec<Vec<Fr>>), bus_mapping::Error> {
        log::debug!(
            "super circuit build_from_witness_block, circuits_params {:?}",
            block.circuits_params
        );

        let (_, rows_needed) = Self::min_num_rows_block(&block);
        let k = log2_ceil(Self::unusable_rows() + rows_needed);
        log::debug!("super circuit needs k = {}", k);

        let circuit =
            SuperCircuit::<Fr, MAX_TXS, MAX_CALLDATA,MAX_INNER_BLOCKS, MOCK_RANDOMNESS>::new_from_block(&block);

        let instance = circuit.instance();
        Ok((k, circuit, instance))
    }
}
