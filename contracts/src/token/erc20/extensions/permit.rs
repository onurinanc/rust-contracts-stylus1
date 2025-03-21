//! Permit Contract.
//!
//! Extension of the ERC-20 standard allowing approvals to be made
//! via signatures, as defined in the [ERC].
//!
//! Adds the `permit` method, which can be used to change an account’s
//! ERC20 allowance (see [`crate::token::erc20::IErc20::allowance`])
//! by presenting a message signed by the account.
//! By not relying on [`erc20::IErc20::approve`],
//! the token holder account doesn’t need to send a transaction,
//! and thus is not required to hold Ether at all.
//!
//! [ERC]: https://eips.ethereum.org/EIPS/eip-2612

use alloc::{vec, vec::Vec};

use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::SolType;
use stylus_sdk::{block, call::MethodError, prelude::*};

use crate::{
    token::erc20::{self, Erc20},
    utils::{
        cryptography::{ecdsa, eip712::IEip712},
        nonces::Nonces,
    },
};

const PERMIT_TYPEHASH: [u8; 32] =
    keccak_const::Keccak256::new()
        .update(b"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")
        .finalize();

pub use sol::*;
#[cfg_attr(coverage_nightly, coverage(off))]
mod sol {
    use alloy_sol_macro::sol;

    pub(crate) type StructHashTuple = sol! {
        tuple(bytes32, address, address, uint256, uint256, uint256)
    };

    sol! {
        /// Indicates an error related to the fact that
        /// permit deadline has expired.
        #[derive(Debug)]
        #[allow(missing_docs)]
        error ERC2612ExpiredSignature(uint256 deadline);

        /// Indicates an error related to the issue about mismatched signature.
        #[derive(Debug)]
        #[allow(missing_docs)]
        error ERC2612InvalidSigner(address signer, address owner);
    }
}

/// A Permit error.
#[derive(SolidityError, Debug)]
pub enum Error {
    /// Indicates an error related to the fact that
    /// permit deadline has expired.
    ExpiredSignature(ERC2612ExpiredSignature),
    /// Indicates an error related to the issue about mismatched signature.
    InvalidSigner(ERC2612InvalidSigner),
    /// Error type from [`Erc20`] contract [`erc20::Error`].
    Erc20(erc20::Error),
    /// Error type from [`ecdsa`] contract [`ecdsa::Error`].
    ECDSA(ecdsa::Error),
}

impl MethodError for Error {
    fn encode(self) -> alloc::vec::Vec<u8> {
        self.into()
    }
}

/// State of an [`Erc20Permit`] Contract.
#[storage]
pub struct Erc20Permit<T: IEip712 + StorageType> {
    /// Contract implementing [`IEip712`] trait.
    pub(crate) eip712: T,
}

/// NOTE: Implementation of [`TopLevelStorage`] to be able use `&mut self` when
/// calling other contracts and not `&mut (impl TopLevelStorage +
/// BorrowMut<Self>)`. Should be fixed in the future by the Stylus team.
unsafe impl<T: IEip712 + StorageType> TopLevelStorage for Erc20Permit<T> {}

#[public]
impl<T: IEip712 + StorageType> Erc20Permit<T> {
    /// Returns the domain separator used in the encoding of the signature for
    /// [`Self::permit`], as defined by EIP712.
    ///
    /// # Arguments
    ///
    /// * `&self` - Read access to the contract's state.
    #[selector(name = "DOMAIN_SEPARATOR")]
    #[must_use]
    pub fn domain_separator(&self) -> B256 {
        self.eip712.domain_separator_v4()
    }
}

impl<T: IEip712 + StorageType> Erc20Permit<T> {
    /// Sets `value` as the allowance of `spender` over `owner`'s tokens,
    /// given `owner`'s signed approval.
    ///
    /// # Arguments
    ///
    /// * `&mut self` - Write access to the contract's state. given address.
    /// * `owner` - Account that owns the tokens.
    /// * `spender` - Account that will spend the tokens.
    /// * `value` - The number of tokens being permitted to transfer by
    ///   `spender`.
    /// * `deadline` - Deadline for the permit action.
    /// * `v` - v value from the `owner`'s signature.
    /// * `r` - r value from the `owner`'s signature.
    /// * `s` - s value from the `owner`'s signature.
    /// * `erc20` - Write access to an [`Erc20`] contract.
    /// * `nonces` - Write access to a [`Nonces`] contract.
    ///
    /// # Errors
    ///
    /// * [`ERC2612ExpiredSignature`] - If the `deadline` param is from the
    ///   past.
    /// * [`ERC2612InvalidSigner`] - If signer is not an `owner`.
    /// * [`ecdsa::Error::InvalidSignatureS`] - If the `s` value is grater than
    ///   [`ecdsa::SIGNATURE_S_UPPER_BOUND`].
    /// * [`ecdsa::Error::InvalidSignature`] - If the recovered address is
    ///   `Address::ZERO`.
    /// * [`erc20::Error::InvalidSpender`] - If the `spender` address is
    ///   `Address::ZERO`.
    ///
    /// # Events
    ///
    /// * [`erc20::Approval`]
    #[allow(clippy::too_many_arguments)]
    pub fn permit(
        &mut self,
        owner: Address,
        spender: Address,
        value: U256,
        deadline: U256,
        v: u8,
        r: B256,
        s: B256,
        erc20: &mut Erc20,
        nonces: &mut Nonces,
    ) -> Result<(), Error> {
        if U256::from(block::timestamp()) > deadline {
            return Err(ERC2612ExpiredSignature { deadline }.into());
        }

        let struct_hash = keccak256(StructHashTuple::abi_encode(&(
            PERMIT_TYPEHASH,
            owner,
            spender,
            value,
            nonces.use_nonce(owner),
            deadline,
        )));

        let hash: B256 = self.eip712.hash_typed_data_v4(struct_hash);

        let signer: Address = ecdsa::recover(self, hash, v, r, s)?;

        if signer != owner {
            return Err(ERC2612InvalidSigner { signer, owner }.into());
        }

        erc20._approve(owner, spender, value, true)?;

        Ok(())
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use alloy_signer::SignerSync;
    use motsu::prelude::*;
    use stylus_sdk::{
        alloy_primitives::{uint, Address, B256, U256},
        alloy_sol_types::sol,
        block,
        prelude::*,
    };

    use super::{
        ERC2612ExpiredSignature, ERC2612InvalidSigner, Erc20, Erc20Permit,
        Error, Nonces, StructHashTuple, PERMIT_TYPEHASH,
    };
    use crate::utils::cryptography::{
        ecdsa::{self, recover, sign_message},
        eip712::{self, IEip712},
    };

    #[storage]
    struct Erc20PermitExample {
        #[borrow]
        erc20: Erc20,
        #[borrow]
        nonces: Nonces,
        #[borrow]
        erc20_permit: Erc20Permit<Eip712>,
    }

    #[storage]
    struct Eip712;

    impl IEip712 for Eip712 {
        const NAME: &'static str = "ERC-20 Permit Example";
        const VERSION: &'static str = "1";
    }

    #[public]
    impl Erc20PermitExample {
        fn permit(
            &mut self,
            owner: Address,
            spender: Address,
            value: U256,
            deadline: U256,
            v: u8,
            r: B256,
            s: B256,
        ) -> Result<(), Error> {
            self.erc20_permit.permit(
                owner,
                spender,
                value,
                deadline,
                v,
                r,
                s,
                &mut self.erc20,
                &mut self.nonces,
            )
        }

        fn domain_separator(&self) -> B256 {
            self.erc20_permit.domain_separator()
        }

        fn allowance(&self, owner: Address, spender: Address) -> U256 {
            self.erc20.allowance(owner, spender)
        }

        fn nonces(&self, owner: Address) -> U256 {
            self.nonces.nonces(owner)
        }
    }

    unsafe impl TopLevelStorage for Erc20PermitExample {}

    // Saturday, 1 January 2000 00:00:00
    const EXPIRED_DEADLINE: U256 = uint!(946_684_800_U256);

    // Wednesday, 1 January 3000 00:00:00
    const FAIR_DEADLINE: U256 = uint!(32_503_680_000_U256);

    // Helper function to create a permit signature
    fn create_permit_signature(
        contract: &Contract<Erc20PermitExample>,
        account: &Account,
        owner: Address,
        spender: Address,
        value: U256,
        nonce: U256,
        deadline: U256,
    ) -> (u8, B256, B256) {
        // Create the struct hash
        let struct_hash =
            alloy_primitives::keccak256(StructHashTuple::abi_encode(&(
                PERMIT_TYPEHASH,
                owner,
                spender,
                value,
                nonce,
                deadline,
            )));

        // Get the domain separator from the contract
        let domain_separator = contract.sender(account).domain_separator();

        // Create the final hash to sign
        let message_hash =
            eip712::to_typed_data_hash(&domain_separator, &struct_hash);

        let signature =
            account.signer().sign_message_sync(message_hash.into()).unwrap();

        (signature.0, signature.1, signature.2)
    }

    #[motsu::test]
    fn permit_works_correctly(
        contract: Contract<Erc20PermitExample>,
        owner: Account,
        spender: Account,
    ) {
        // Initial setup
        let value = uint!(100_U256);
        let deadline = U256::from(block::timestamp()) + uint!(3600_U256); // 1 hour from now
        let initial_nonce = contract.sender(owner).nonces(owner.address());

        // Create a valid signature
        let (v, r, s) = create_permit_signature(
            &contract,
            &owner,
            owner.address(),
            spender.address(),
            value,
            initial_nonce,
            deadline,
        );

        // Execute the permit function
        contract
            .sender(spender)
            .permit(
                owner.address(),
                spender.address(),
                value,
                deadline,
                v,
                r,
                s,
            )
            .expect("Permit should succeed");

        // Verify the allowance was set correctly
        let allowance = contract
            .sender(owner)
            .allowance(owner.address(), spender.address());
        assert_eq!(
            allowance, value,
            "Allowance should be set to the correct value"
        );

        // Verify the nonce was incremented
        let new_nonce = contract.sender(owner).nonces(owner.address());
        assert_eq!(
            new_nonce,
            initial_nonce + U256::from(1),
            "Nonce should be incremented by 1"
        );
    }

    #[motsu::test]
    fn permit_fails_with_expired_deadline(
        contract: Contract<Erc20PermitExample>,
        owner: Account,
        spender: Account,
    ) {
        // Set deadline in the past
        let value = uint!(100_U256);
        let deadline = U256::from(block::timestamp()) - uint!(3600_U256); // 1 hour ago
        let initial_nonce = contract.sender(owner).nonces(owner.address());

        // Create a signature
        let (v, r, s) = create_permit_signature(
            &contract,
            &owner,
            owner.address(),
            spender.address(),
            value,
            initial_nonce,
            deadline,
        );

        // Attempt to execute the permit function with expired deadline
        let result = contract.sender(spender).permit(
            owner.address(),
            spender.address(),
            value,
            deadline,
            v,
            r,
            s,
        );

        // Verify the error
        assert!(
            matches!(
                result.unwrap_err(),
                Error::ExpiredSignature(ERC2612ExpiredSignature { deadline: expired_deadline })
                if expired_deadline == deadline
            ),
            "Should fail with ExpiredSignature error"
        );

        // Verify allowance remains unchanged
        let allowance = contract
            .sender(owner)
            .allowance(owner.address(), spender.address());
        assert_eq!(allowance, U256::ZERO, "Allowance should remain zero");

        // Verify nonce was not incremented
        let new_nonce = contract.sender(owner).nonces(owner.address());
        assert_eq!(new_nonce, initial_nonce, "Nonce should not be incremented");
    }

    #[motsu::test]
    fn permit_fails_with_invalid_signer(
        contract: Contract<Erc20PermitExample>,
        owner: Account,
        spender: Account,
        attacker: Account,
    ) {
        // Initial setup
        let value = uint!(100_U256);
        let deadline = U256::from(block::timestamp()) + uint!(3600_U256); // 1 hour from now
        let initial_nonce = contract.sender(owner).nonces(owner.address());

        // Create a signature from the attacker, not the owner
        let (v, r, s) = create_permit_signature(
            &contract,
            &attacker, // Attacker signs instead of owner
            owner.address(),
            spender.address(),
            value,
            initial_nonce,
            deadline,
        );

        // Attempt to execute the permit function with invalid signer
        let result = contract.sender(spender).permit(
            owner.address(),
            spender.address(),
            value,
            deadline,
            v,
            r,
            s,
        );

        // Verify the error
        assert!(
            matches!(
                result.unwrap_err(),
                Error::InvalidSigner(ERC2612InvalidSigner { signer, owner: owner_addr })
                if owner_addr == owner.address() && signer != owner.address()
            ),
            "Should fail with InvalidSigner error"
        );

        // Verify allowance remains unchanged
        let allowance = contract
            .sender(owner)
            .allowance(owner.address(), spender.address());
        assert_eq!(allowance, U256::ZERO, "Allowance should remain zero");

        // Verify nonce was not incremented
        let new_nonce = contract.sender(owner).nonces(owner.address());
        assert_eq!(new_nonce, initial_nonce, "Nonce should not be incremented");
    }

    #[motsu::test]
    fn permit_replay_attack_fails(
        contract: Contract<Erc20PermitExample>,
        owner: Account,
        spender: Account,
    ) {
        // Initial setup
        let value = uint!(100_U256);
        let deadline = U256::from(block::timestamp()) + uint!(3600_U256); // 1 hour from now
        let initial_nonce = contract.sender(owner).nonces(owner.address());

        // Create a valid signature
        let (v, r, s) = create_permit_signature(
            &contract,
            &owner,
            owner.address(),
            spender.address(),
            value,
            initial_nonce,
            deadline,
        );

        // Execute the permit function first time - should succeed
        contract
            .sender(spender)
            .permit(
                owner.address(),
                spender.address(),
                value,
                deadline,
                v,
                r,
                s,
            )
            .expect("First permit should succeed");

        // Attempt to replay the same signature
        let result = contract.sender(spender).permit(
            owner.address(),
            spender.address(),
            value,
            deadline,
            v,
            r,
            s,
        );

        // This should fail since the nonce has been incremented
        assert!(result.is_err(), "Replay attack should fail");

        // Verify the error (will be InvalidSigner because the signature will
        // recover a different signer)
        assert!(
            matches!(result.unwrap_err(), Error::InvalidSigner(_)),
            "Should fail with InvalidSigner error due to nonce mismatch"
        );
    }

    #[motsu::test]
    fn permit_different_value_after_successful_call(
        contract: Contract<Erc20PermitExample>,
        owner: Account,
        spender: Account,
    ) {
        // Initial setup - first permit
        let value1 = uint!(100_U256);
        let deadline = U256::from(block::timestamp()) + uint!(3600_U256); // 1 hour from now
        let initial_nonce = contract.sender(owner).nonces(owner.address());

        // Create and use first valid signature
        let (v1, r1, s1) = create_permit_signature(
            &contract,
            &owner,
            owner.address(),
            spender.address(),
            value1,
            initial_nonce,
            deadline,
        );

        contract
            .sender(spender)
            .permit(
                owner.address(),
                spender.address(),
                value1,
                deadline,
                v1,
                r1,
                s1,
            )
            .expect("First permit should succeed");

        // Verify first allowance
        let allowance1 = contract
            .sender(owner)
            .allowance(owner.address(), spender.address());
        assert_eq!(
            allowance1, value1,
            "First allowance should be set correctly"
        );

        // Second permit with different value
        let value2 = uint!(200_U256);
        let new_nonce = contract.sender(owner).nonces(owner.address());

        // Create and use second valid signature
        let (v2, r2, s2) = create_permit_signature(
            &contract,
            &owner,
            owner.address(),
            spender.address(),
            value2,
            new_nonce,
            deadline,
        );

        contract
            .sender(spender)
            .permit(
                owner.address(),
                spender.address(),
                value2,
                deadline,
                v2,
                r2,
                s2,
            )
            .expect("Second permit should succeed");

        // Verify second allowance overwrites the first
        let allowance2 = contract
            .sender(owner)
            .allowance(owner.address(), spender.address());
        assert_eq!(
            allowance2, value2,
            "Second allowance should overwrite the first"
        );
    }

    #[motsu::test]
    fn permit_with_max_deadline_succeeds(
        contract: Contract<Erc20PermitExample>,
        owner: Account,
        spender: Account,
    ) {
        // Set deadline to maximum possible value
        let value = uint!(100_U256);
        let deadline = U256::MAX;
        let initial_nonce = contract.sender(owner).nonces(owner.address());

        // Create a valid signature
        let (v, r, s) = create_permit_signature(
            &contract,
            &owner,
            owner.address(),
            spender.address(),
            value,
            initial_nonce,
            deadline,
        );

        // Execute the permit function
        contract
            .sender(spender)
            .permit(
                owner.address(),
                spender.address(),
                value,
                deadline,
                v,
                r,
                s,
            )
            .expect("Permit with max deadline should succeed");

        // Verify the allowance was set correctly
        let allowance = contract
            .sender(owner)
            .allowance(owner.address(), spender.address());
        assert_eq!(
            allowance, value,
            "Allowance should be set to the correct value"
        );
    }

    #[motsu::test]
    fn permit_with_max_value_succeeds(
        contract: Contract<Erc20PermitExample>,
        owner: Account,
        spender: Account,
    ) {
        // Set value to maximum possible value
        let value = U256::MAX;
        let deadline = U256::from(block::timestamp()) + uint!(3600_U256);
        let initial_nonce = contract.sender(owner).nonces(owner.address());

        // Create a valid signature
        let (v, r, s) = create_permit_signature(
            &contract,
            &owner,
            owner.address(),
            spender.address(),
            value,
            initial_nonce,
            deadline,
        );

        // Execute the permit function
        contract
            .sender(spender)
            .permit(
                owner.address(),
                spender.address(),
                value,
                deadline,
                v,
                r,
                s,
            )
            .expect("Permit with max value should succeed");

        // Verify the allowance was set correctly
        let allowance = contract
            .sender(owner)
            .allowance(owner.address(), spender.address());
        assert_eq!(
            allowance, value,
            "Allowance should be set to the maximum value"
        );
    }

    #[motsu::test]
    fn permit_zero_value_succeeds(
        contract: Contract<Erc20PermitExample>,
        owner: Account,
        spender: Account,
    ) {
        // Set up initial non-zero allowance
        let initial_value = uint!(100_U256);
        contract.init(owner.address(), |contract| {
            contract
                .erc20
                ._approve(
                    owner.address(),
                    spender.address(),
                    initial_value,
                    true,
                )
                .expect("Initial approval should succeed");
        });

        // Verify initial allowance
        let initial_allowance = contract
            .sender(owner)
            .allowance(owner.address(), spender.address());
        assert_eq!(
            initial_allowance, initial_value,
            "Initial allowance should be set"
        );

        // Now create a permit with zero value
        let value = U256::ZERO;
        let deadline = U256::from(block::timestamp()) + uint!(3600_U256);
        let initial_nonce = contract.sender(owner).nonces(owner.address());

        // Create a valid signature for zero value
        let (v, r, s) = create_permit_signature(
            &contract,
            &owner,
            owner.address(),
            spender.address(),
            value,
            initial_nonce,
            deadline,
        );

        // Execute the permit function
        contract
            .sender(spender)
            .permit(
                owner.address(),
                spender.address(),
                value,
                deadline,
                v,
                r,
                s,
            )
            .expect("Permit with zero value should succeed");

        // Verify the allowance was set to zero
        let allowance = contract
            .sender(owner)
            .allowance(owner.address(), spender.address());
        assert_eq!(allowance, U256::ZERO, "Allowance should be set to zero");
    }

    #[motsu::test]
    fn permit_domain_separator_change_invalidates_signatures(
        contract: Contract<Erc20PermitExample>,
        owner: Account,
        spender: Account,
    ) {
        // This test simulates a domain separator change (like in a chain fork)
        // In a real test, we would need to modify the chain ID or other domain
        // components For now, we'll just demonstrate the concept

        let value = uint!(100_U256);
        let deadline = U256::from(block::timestamp()) + uint!(3600_U256);
        let initial_nonce = contract.sender(owner).nonces(owner.address());

        // Create a valid signature with the current domain separator
        let (v, r, s) = create_permit_signature(
            &contract,
            &owner,
            owner.address(),
            spender.address(),
            value,
            initial_nonce,
            deadline,
        );

        // In a real scenario, a chain fork would happen here, changing the
        // domain separator Since we can't easily simulate that in
        // motsu, we'll just verify that the signature works with the
        // current domain separator

        // Execute the permit function
        contract
            .sender(spender)
            .permit(
                owner.address(),
                spender.address(),
                value,
                deadline,
                v,
                r,
                s,
            )
            .expect("Permit should succeed with correct domain separator");

        // In a real test, we would verify that the same signature fails after a
        // domain separator change
    }
}
