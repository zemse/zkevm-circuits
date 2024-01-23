use gadgets::util::Scalar;
// use halo2_proofs::halo2curves::bn256::Fr;

use bus_mapping::operation::Target as RwTableTag;

use super::*;

/// Tag to identify the field in a Init State Table row
/// Keep the sequence consistent with OpcodeId for scalar
#[derive(Clone, Copy, Debug)]
pub enum InitStateFieldTag {
    /// Storage field, field_tag is zero for AccountStorage
    Storage = 0,
    /// Nonce field
    Nonce = 1,
    /// Balance field
    Balance = 2,
    /// CodeHash field
    CodeHash = 3,
}
impl_expr!(InitStateFieldTag);

/// Table with Init State entries
#[derive(Clone, Debug)]
pub struct InitStateTable {
    /// Account Address
    pub address: Column<Advice>,
    /// InitStateFieldTag
    pub field_tag: Column<Advice>,
    /// Account Storage Key if InitStateFieldTag is Storage
    pub storage_key: WordLoHi<Column<Advice>>,
    /// Value
    pub value: WordLoHi<Column<Advice>>,
}

impl InitStateTable {
    /// Construct a new InitStateTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            address: meta.advice_column(),
            field_tag: meta.advice_column(),
            storage_key: WordLoHi::new([meta.advice_column(), meta.advice_column()]),
            value: WordLoHi::new([meta.advice_column(), meta.advice_column()]),
        }
    }

    /// Assign the `InitStateTable` from a `RwMap`.
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        rws: &RwMap,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "init state table",
            |mut region| {
                let init_state_table_columns =
                    <InitStateTable as LookupTable<F>>::advice_columns(self);
                let mut offset = 0;

                for column in init_state_table_columns {
                    region.assign_advice(
                        || "is table all-zero row",
                        column,
                        offset,
                        || Value::known(F::ZERO),
                    )?;
                }
                offset += 1;

                let zero_word = WordLoHi::new([F::ZERO, F::ZERO]).into_value();

                // TODO remove duplicates
                let account_rws: &Vec<Rw> = rws.0.get(&RwTableTag::Account).unwrap();
                for rw in account_rws.iter() {
                    let address: F = rw.address().unwrap().to_scalar().unwrap();
                    let field_tag: F = match rw.field_tag().unwrap() {
                        1 => InitStateFieldTag::Nonce.scalar(),
                        2 => InitStateFieldTag::Balance.scalar(),
                        3 => InitStateFieldTag::CodeHash.scalar(),
                        _ => unreachable!(),
                    };

                    region.assign_advice(
                        || format!("init state table row {offset} address"),
                        self.address,
                        offset,
                        || Value::known(address),
                    )?;
                    region.assign_advice(
                        || format!("init state table row {offset} field_tag"),
                        self.field_tag,
                        offset,
                        || Value::known(field_tag),
                    )?;
                    zero_word.assign_advice(
                        &mut region,
                        || format!("init state table row {offset} storage_key"),
                        self.storage_key,
                        offset,
                    )?;
                    WordLoHi::from(rw.value_assignment())
                        .into_value()
                        .assign_advice(
                            &mut region,
                            || format!("init state table row {offset} value"),
                            self.value,
                            offset,
                        )?;
                    offset += 1;
                }

                // TODO remove duplicates
                let storage_rws: &Vec<Rw> = rws.0.get(&RwTableTag::Storage).unwrap();
                for rw in storage_rws.iter() {
                    let address: F = rw.address().unwrap().to_scalar().unwrap();
                    let field_tag: F = F::from(InitStateFieldTag::Storage as u64);
                    let storage_key = WordLoHi::from(rw.storage_key().unwrap()).into_value();
                    let storage_value = WordLoHi::from(rw.value_assignment()).into_value();

                    region.assign_advice(
                        || format!("is table row {offset} address"),
                        self.address,
                        offset,
                        || Value::known(address),
                    )?;
                    region.assign_advice(
                        || format!("is table row {offset} field_tag"),
                        self.field_tag,
                        offset,
                        || Value::known(field_tag),
                    )?;

                    storage_key.assign_advice(
                        &mut region,
                        || format!("is table row {offset} storage_key"),
                        self.storage_key,
                        offset,
                    )?;
                    storage_value.assign_advice(
                        &mut region,
                        || format!("init state table row {offset} value"),
                        self.value,
                        offset,
                    )?;
                    offset += 1;
                }

                Ok(())
            },
        )
    }
}

impl<F: Field> LookupTable<F> for InitStateTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.address.into(),
            self.field_tag.into(),
            self.storage_key.lo().into(),
            self.storage_key.hi().into(),
            self.value.lo().into(),
            self.value.hi().into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("address"),
            String::from("field_tag"),
            String::from("storage_key_lo"),
            String::from("storage_key_hi"),
            String::from("value_lo"),
            String::from("value_hi"),
        ]
    }
}
