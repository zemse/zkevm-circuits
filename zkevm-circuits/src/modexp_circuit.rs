//! The Modexp circuit is responsible for modexp operations on big integer from precompiled contract
//! calls ModExp, current the size of supported integer is up to 32 bytes (U256)

#[cfg(any(feature = "test", test, feature = "test-circuits"))]
mod dev;
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
mod test;

use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error},
};

use crate::{
    table::ModExpTable,
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness,
};
use bus_mapping::circuit_input_builder::BigModExp;
use eth_types::{Field, Word};

//use misc_precompiled_circuit::value_for_assign;
use misc_precompiled_circuit::circuits::{
    modexp::{ModExpChip, Number},
    range::{RangeCheckChip, RangeCheckConfig},
    CommonGateConfig as ModExpConfig, Limb,
};

/// ModExp circuit config
#[derive(Clone, Debug)]
pub struct ModExpCircuitConfig {
    modexp_config: ModExpConfig,
    rangecheck_config: RangeCheckConfig,
    modexp_table: ModExpTable,
}

impl<F: Field> SubCircuitConfig<F> for ModExpCircuitConfig {
    type ConfigArgs = ModExpTable;

    /// Return a new ModExpCircuitConfig
    fn new(meta: &mut ConstraintSystem<F>, modexp_table: Self::ConfigArgs) -> Self {
        let rangecheck_config = RangeCheckChip::configure(meta);
        let modexp_config = ModExpChip::configure(meta, &rangecheck_config);
        Self {
            rangecheck_config,
            modexp_config,
            modexp_table,
        }
    }
}

impl ModExpCircuitConfig {
    pub(crate) fn assign_group<F: Field>(
        &self,
        region: &mut Region<F>,
        table_offset: usize,
        mut calc_offset: usize,
        event: &BigModExp,
        modexp_chip: &ModExpChip<F>,
        range_check_chip: &mut RangeCheckChip<F>,
    ) -> Result<usize, Error> {
        let base = self.assign_value(region, table_offset, self.modexp_table.base, &event.base)?;
        let exp =
            self.assign_value(region, table_offset, self.modexp_table.exp, &event.exponent)?;
        let modulus = self.assign_value(
            region,
            table_offset,
            self.modexp_table.modulus,
            &event.modulus,
        )?;
        let ret = modexp_chip.mod_exp(
            region,
            range_check_chip,
            &mut calc_offset,
            &base,
            &exp,
            &modulus,
        )?;
        for i in 0..4 {
            region.assign_fixed(
                || format!("modexp table head {}", table_offset + i),
                self.modexp_table.q_head,
                table_offset + i,
                || Value::known(if i == 0 { F::ONE } else { F::ZERO }),
            )?;

            ret.limbs[i]
                .cell
                .clone()
                .expect("should has assigned after modexp")
                .copy_advice(
                    || "copy to result limbs",
                    region,
                    self.modexp_table.result,
                    table_offset + i,
                )?;
        }
        Ok(calc_offset)
    }

    fn assign_value<F: Field>(
        &self,
        region: &mut Region<F>,
        offset: usize,
        col: Column<Advice>,
        value: &Word,
    ) -> Result<Number<F>, Error> {
        let limbs_v = ModExpTable::split_u256_108bit_limbs(value);
        let native_v = ModExpTable::native_u256(value);
        let mut limbs = Vec::new();

        for (i, limb) in limbs_v.into_iter().enumerate() {
            let fv = F::from_u128(limb);
            let c = region.assign_advice(
                || "assign modexp limb",
                col,
                offset + i,
                || Value::known(fv),
            )?;
            limbs.push(Limb::new(Some(c), fv));
        }
        let c = region.assign_advice(
            || "assign modexp native",
            col,
            offset + 3,
            || Value::known(native_v),
        )?;
        limbs.push(Limb::new(Some(c), native_v));
        Ok(Number {
            limbs: limbs.try_into().expect("just 4 pushes"),
        })
    }
}

const MODEXPCONFIG_EACH_CHIP_ROWS: usize = 39962;

/// ModExp circuit for precompile modexp
#[derive(Clone, Debug, Default)]
pub struct ModExpCircuit<F: Field>(Vec<BigModExp>, std::marker::PhantomData<F>);

impl<F: Field> SubCircuit<F> for ModExpCircuit<F> {
    type Config = ModExpCircuitConfig;

    fn unusable_rows() -> usize {
        // No column queried at more than 4 distinct rotations, so returns 8 as
        // minimum unusable rows.
        8
    }

    fn new_from_block(block: &witness::Block<F>) -> Self {
        let event_limit = block.circuits_params.max_keccak_rows / MODEXPCONFIG_EACH_CHIP_ROWS;

        let mut exp_events = block.get_big_modexp();
        if event_limit != 0 {
            assert!(
                exp_events.len() <= event_limit,
                "no enough rows for modexp circuit, expected {}, limit {}",
                exp_events.len(),
                event_limit,
            );
            exp_events.resize(event_limit, Default::default());
            log::info!("modexp circuit work with maxium {} entries", event_limit);
        }

        Self(exp_events, Default::default())
    }

    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        let exp_events = block.get_big_modexp();
        let real_len = exp_events.len() * MODEXPCONFIG_EACH_CHIP_ROWS;
        (
            real_len,
            real_len
                .max(block.circuits_params.max_keccak_rows)
                .max(4096),
        )
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        _challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let modexp_chip = ModExpChip::new(config.modexp_config.clone());
        let mut range_chip = RangeCheckChip::new(config.rangecheck_config.clone());

        layouter.assign_region(
            || "modexp circuit",
            |mut region| {
                range_chip.initialize(&mut region)?;
                let _modexp_count = self.0.len();
                let mut calc_offset = 0;
                for (n, event) in self.0.iter().enumerate() {
                    calc_offset = config.assign_group(
                        &mut region,
                        n * 4,
                        calc_offset,
                        event,
                        &modexp_chip,
                        &mut range_chip,
                    )?;
                }
                //assert_eq!(max(calc_offset, range_chip.offset), MODEXPCONFIG_EACH_CHIP_ROWS *
                // modexp_count);
                Ok(())
            },
        )?;

        config.modexp_table.fill_blank(layouter)
    }
}
