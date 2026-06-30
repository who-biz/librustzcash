use std::collections::HashMap;

use sapling::note_encryption::{PreparedIncomingViewingKey, SaplingDomain};
use zcash_note_encryption::{try_note_decryption, try_output_recovery_with_ovk};
use zcash_primitives::{
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    transaction::components::{amount::NonNegativeAmount, sapling::zip212_enforcement},
    transaction::Transaction,
    zip32::Scope,
};

use crate::{data_api::DecryptedTransaction, keys::UnifiedFullViewingKey};

#[cfg(feature = "orchard")]
use orchard::note_encryption::OrchardDomain;

/// An enumeration of the possible relationships a TXO can have to the wallet.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TransferType {
    /// The output was received on one of the wallet's external addresses via decryption using the
    /// associated incoming viewing key, or at one of the wallet's transparent addresses.
    Incoming,
    /// The output was received on one of the wallet's external addresses via decryption using the
    /// associated incoming viewing key AND is external-ovk-recoverable.
    IncomingChange,
    /// The output was received on one of the wallet's internal-only shielded addresses via trial
    /// decryption using one of the wallet's internal incoming viewing keys.
    WalletInternal,
    /// The output was decrypted using one of the wallet's outgoing viewing keys, or was created
    /// in a transaction constructed by this wallet.
    Outgoing,
}

/// A decrypted shielded output.
pub struct DecryptedOutput<Note, AccountId> {
    index: usize,
    note: Note,
    account: AccountId,
    memo: MemoBytes,
    transfer_type: TransferType,
}

impl<Note, AccountId: Copy> DecryptedOutput<Note, AccountId> {
    pub fn new(
        index: usize,
        note: Note,
        account: AccountId,
        memo: MemoBytes,
        transfer_type: TransferType,
    ) -> Self {
        Self {
            index,
            note,
            account,
            memo,
            transfer_type,
        }
    }

    /// The index of the output within the shielded outputs of the Sapling bundle or the actions of
    /// the Orchard bundle, depending upon the type of [`Self::note`].
    pub fn index(&self) -> usize {
        self.index
    }

    /// The note within the output.
    pub fn note(&self) -> &Note {
        &self.note
    }

    /// The account that decrypted the note.
    pub fn account(&self) -> &AccountId {
        &self.account
    }

    /// The memo bytes included with the note.
    pub fn memo(&self) -> &MemoBytes {
        &self.memo
    }

    /// Returns a [`TransferType`] value that is determined based upon what type of key was used to
    /// decrypt the transaction.
    pub fn transfer_type(&self) -> TransferType {
        self.transfer_type
    }
}

impl<A> DecryptedOutput<sapling::Note, A> {
    pub fn note_value(&self) -> NonNegativeAmount {
        NonNegativeAmount::from_u64(self.note.value().inner())
            .expect("Sapling note value is expected to have been validated by consensus.")
    }
}

#[cfg(feature = "orchard")]
impl<A> DecryptedOutput<orchard::note::Note, A> {
    pub fn note_value(&self) -> NonNegativeAmount {
        NonNegativeAmount::from_u64(self.note.value().inner())
            .expect("Orchard note value is expected to have been validated by consensus.")
    }
}

/// Scans a [`Transaction`] for any information that can be decrypted by the set of
/// [`UnifiedFullViewingKey`]s.
pub fn decrypt_transaction<'a, P: consensus::Parameters, AccountId: Copy>(
    params: &P,
    height: BlockHeight,
    tx: &'a Transaction,
    ufvks: &HashMap<AccountId, UnifiedFullViewingKey>,
) -> DecryptedTransaction<'a, AccountId> {
    let zip212_enforcement = zip212_enforcement(params, height);
    let sapling_bundle = tx.sapling_bundle();
    let sapling_outputs = sapling_bundle
        .iter()
        .flat_map(|bundle| {
            ufvks
                .iter()
                .flat_map(|(account, ufvk)| ufvk.sapling().into_iter().map(|dfvk| (*account, dfvk)))
                .flat_map(|(account, dfvk)| {
                    let sapling_domain = SaplingDomain::new(zip212_enforcement);
                    let ivk_external =
                        PreparedIncomingViewingKey::new(&dfvk.to_ivk(Scope::External));
                    let ivk_internal =
                        PreparedIncomingViewingKey::new(&dfvk.to_ivk(Scope::Internal));

                    let ovk_internal = dfvk.to_ovk(Scope::Internal);
                    let ovk_external = dfvk.to_ovk(Scope::External);

                    bundle
                        .shielded_outputs()
                        .iter()
                        .enumerate()
                        .flat_map(move |(index, output)| {
                            // first, try decrypting with external ivk

                            //TODO: (Biz) if we don't omit middle argument of map (note,_,memo), we can return address
                            // as well, on rescan for wallets. currently, we don't regenerate that information.
                            // I do not see a reason this needs withheld for externally scoped key cases

                            try_note_decryption(&sapling_domain, &ivk_external, output).map(|(note, _, memo)| {
                                //TODO: is there a better way to structure these conditions?
                                let is_change = try_output_recovery_with_ovk(
                                    &sapling_domain,
                                    &ovk_external,
                                    output,
                                    output.cv(),
                                    output.out_ciphertext(),
                                )
                                .is_some();

                                let transfer_type = if is_change {
                                    TransferType::IncomingChange
                                } else {
                                    TransferType::Incoming
                                };

                                (
                                    note,
                                    memo,
                                    transfer_type,
                                )
                            }).or_else(|| {
                                    // external ivk did not work, try external ovk recovery next
                                try_output_recovery_with_ovk(
                                    &sapling_domain,
                                    &ovk_external,
                                    output,
                                    output.cv(),
                                    output.out_ciphertext(),
                                )
                               .map(|(note, _, memo)| {
                                   (
                                       note,
                                       memo,
                                       TransferType::Outgoing,
                                   )
                                })
                            }).or_else(|| {
                                    // only try internal key decryptions if externally scoped do not work

                                    //TODO: (Biz) if, at some point, we transition to preferring internal scope, order of
                                    // these conditions should be flipped, to minimize decryption attempts. I'm not sure
                                    // if a failed decrypt is as expensive as a successful one, likely not 
                                try_note_decryption(
                                    &sapling_domain,
                                    &ivk_internal,
                                    output,
                                )
                               .map(|(note, _, memo)| {
                                   (
                                       note,
                                       memo,
                                       TransferType::WalletInternal,
                                   )
                                })
                            }).or_else(|| {
                                // external (ivk/ovk) & internal_ivk did not work, try internal ovk recovery
                                try_output_recovery_with_ovk(
                                    &sapling_domain,
                                    &ovk_internal,
                                    output,
                                    output.cv(),
                                    output.out_ciphertext(),
                                )
                                .map(|(note, _, memo)| {
                                    (
                                         note,
                                         memo,
                                         TransferType::Outgoing,
                                    )
                                })
                            })
                            .into_iter()
                            .map(move |(note, memo, transfer_type)| {
                                //TODO: (Biz) should we return Option<Address> in this as well, for decrypted recipients on rescan?
                                DecryptedOutput::new(
                                    index,
                                    note,
                                    account,
                                    MemoBytes::from_bytes(&memo)
                                        .expect("correct length"),
                                    transfer_type,
                                )
                            })
                        })
                    })
            })
            .collect();

    #[cfg(feature = "orchard")]
    let orchard_bundle = tx.orchard_bundle();
    #[cfg(feature = "orchard")]
    let orchard_outputs = orchard_bundle
        .iter()
        .flat_map(|bundle| {
            ufvks
                .iter()
                .flat_map(|(account, ufvk)| ufvk.orchard().into_iter().map(|fvk| (*account, fvk)))
                .flat_map(|(account, fvk)| {
                    let ivk_external = orchard::keys::PreparedIncomingViewingKey::new(
                        &fvk.to_ivk(Scope::External),
                    );
                    let ivk_internal = orchard::keys::PreparedIncomingViewingKey::new(
                        &fvk.to_ivk(Scope::Internal),
                    );
                    let ovk = fvk.to_ovk(Scope::External);

                    bundle
                        .actions()
                        .iter()
                        .enumerate()
                        .flat_map(move |(index, action)| {
                            let domain = OrchardDomain::for_action(action);
                            let account = account;
                            try_note_decryption(&domain, &ivk_external, action)
                                .map(|ret| (ret, TransferType::Incoming))
                                .or_else(|| {
                                    try_note_decryption(&domain, &ivk_internal, action)
                                        .map(|ret| (ret, TransferType::WalletInternal))
                                })
                                .or_else(|| {
                                    try_output_recovery_with_ovk(
                                        &domain,
                                        &ovk,
                                        action,
                                        action.cv_net(),
                                        &action.encrypted_note().out_ciphertext,
                                    )
                                    .map(|ret| (ret, TransferType::Outgoing))
                                })
                                .into_iter()
                                .map(move |((note, _, memo), transfer_type)| {
                                    DecryptedOutput::new(
                                        index,
                                        note,
                                        account,
                                        MemoBytes::from_bytes(&memo).expect("correct length"),
                                        transfer_type,
                                    )
                                })
                        })
                })
        })
        .collect();

    DecryptedTransaction::new(
        tx,
        sapling_outputs,
        #[cfg(feature = "orchard")]
        orchard_outputs,
    )
}
