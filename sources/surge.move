module surge::surge {
    use moveos_std::account;
    //use std::string;
    use moveos_std::signer;
    use surge::user;
    //use std::vector;

    //==============================================================================================
    // Errors
    //==============================================================================================


    //==============================================================================================
    // Constants
    //==============================================================================================


    //==============================================================================================
    // Structs
    //==============================================================================================

    /// Data structure stored for each msig wallet, including:
    ///     1. msig wallet info (owners, public keys, threshold, e.t.c.)
    ///     2. TxnBook of pending transactions.
    struct SurgeWallet has key {
        info: Info,
        txn_book: TxnBook,
    }

    /// Basic information of multi-sig wallet.
    /// Including owners, public keys, threshold, and wallet name (as metadata).
    struct Info has store, copy, drop {
        // vector of owners
        owners: vector<address>,
        // vector of public_keys that matches owners
        public_keys: vector<vector<u8>>,
        // creation nonce of the safe wallet
        //nonce: u64,
        // signing threshold
        threshold: u8,
        // metadata for wallet information
        //metadata: vector<u8>,
    }

    /// Stores the pending transactions of a multi-sig wallet.
    struct TxnBook has store {
        // Minimum sequence_number in the txn_book.
        // The parameter is updated and used in stale transaction pruning.
        //min_sequence_number: u64,
        // Maximum sequence_number in the txn_book.
        // This parameter is updated when adding new transaction,
        // and is used in stale transaction pruning.
        //max_sequence_number: u64,
        // A map from sequence number to the list of transactions hashes.
        // There can be multiple transaction with the same sequence number
        // in case there are conflicting transactions (E.g. revert transactions).
        // Eventually, only one of the transaction of the same sequence number
        // can be executed.
        // Note that the transaction hash here is different from of transaction
        // hash that is finalized in blockchain. It is a hash of the transaction
        // payload as a temporary identifier to the unique pending transactions.
        //tx_hashes: TableWithLength<u64, vector<vector<u8>>>,
        // A map from transaction payload hash to the Transaction information.
        // Storing the detailed information about the pending transaction, where
        // the index transaction hashes can be obtained from `tx_hashes`.
        pendings: TableWithLength<vector<u8>, Transaction>,
    }

    /// Transaction includes all information needed for a certain transaction
    /// to be executed by the msig wallet, including payload, metadata,
    /// and signatures.
    /// Initially, transaction will have only 1 signature. The signatures are
    /// added when other owners call addSignature. The transaction is ready to
    /// be sent when number of signatures reaches threshold - 1.
    struct Transaction has store, drop, copy {
        // Payload of the transaction to be executed by the msig wallet.
        // Can be an arbitrary transaction payload.
        payload: vector<u8>,
        // Metadata stored on chain to serve as a transaction identifier or memo.
        //metadata: vector<u8>,
        // Signatures collected so far. A map from public key to its corresponding
        // signature.
        signatures: SimpleMap<vector<u8>, vector<u8>>,
    }

    //==============================================================================================
    // Events
    //==============================================================================================

    /// Event handlers for msig wallet. Two events are watched:
    ///     1. `surge.register`
    ///     2. `init_transaction`
    struct SurgeEvent has key {
        register_events: EventHandle<Info>,
        transaction_events: EventHandle<Transaction>
    }

    //==============================================================================================
    // Entry functions
    //==============================================================================================

    /// Register the msig wallet in smart contract
    ///
    /// This shall be the first transaction sent by the msig wallet.
    /// The transaction records basic information of the msig wallet and its owners
    ///
    /// # Parameters
    /// * `msig`: signer object of the surge multi-sig wallet.
    /// * `owners`: address of owners
    /// * `public_keys`: public keys of owners
    /// * `threshold`: approval threshold
    ///
    /// # Aborts
    /// * `creator::EMSIG_NOT_FOUND`: msig address is not found in creator.
    /// * `registry::EADDRESS_NOT_REGISTRERED`: address is not registered at registry.
    /// * `registry::EMSIG_NOT_REGISTERED`: msig is not registered in pendings
    ///         under the owner resource.
    ///
    /// # Emits
    /// * `register_events`
    public entry fun register(
        msig: &signer,
        owners: vector<address>,
        public_keys: vector<vector<u8>>,
        threshold: u8,
        //metadata: vector<u8>
    ) {
        let msig_address = signer::address_of(msig);
        // HACK: Avoid web wallet throw an error during transaction simulation.
        // msig account is created in account.move at the call
        // `creator::init_wallet_creation`. However, a signature on this transaction
        // from wallet creation initiator is needed before calling
        // `creator::init_wallet_creation`. Thus add this temporary hack to allow
        // user to sign on register transaction.
        if (!account::exists_at(msig_address)) {
            return
        };

        // register to `surge.SurgeWallet`.
        //create_surge(msig, owners, public_keys, nonce, threshold, metadata);
        create_surge(msig, owners, public_keys, threshold);
        // register to each owner's user profile
        //add_to_registry(msig, owners, msig_address)
        add_to_registry(owners, msig_address)
    }

    /// Accepts pending msig wallet co-owner invitation
    ///
    /// This logs msig wallet in user's msig list
    ///
    /// # Parameters
    /// * `s`: signer object of user
    /// * `msig_address`: address of msig wallet
    /// * `public_keys`: public keys of owners
    /// * `threshold`: approval threshold
    ///
    /// # Aborts
    /// * `creator::EMSIG_NOT_FOUND`: msig address is not found in creator.
    /// * `registry::EADDRESS_NOT_REGISTRERED`: address is not registered at registry.
    /// * `registry::EMSIG_NOT_REGISTERED`: msig is not registered in pendings
    ///         under the owner resource.
    ///
    /// # Emits
    /// * `register_events`
    public entry fun accept_invitation(
        s: &signer,
        msig_address: address
        //metadata: vector<u8>
    ) {
        let owner_address = signer::address_of(s);
        if (!account::exists_at(owner_address)) {
            return
        };
        user::confirm_pending_msig(owner_address, msig_address)
    }

    //==============================================================================================
    // Internal functions
    //==============================================================================================

    /// Create and publish the data at msig wallet. Called by register function.
    ///
    /// # Parameters
    /// * `msig`: signer object of the msig wallet.
    /// * `owners`: owner address vector.
    /// * `public_keys`: owner public keys.
    /// * `nonce`: creation nonce.
    /// * `threshold`: signing threshold.
    /// * `metadata`: wallet information.
    ///
    /// # Emits
    /// * `register_events`
    fun create_surge(
        msig: &signer,
        owners: vector<address>,
        public_keys: vector<vector<u8>>,
        //nonce: u64,
        threshold: u8,
        //metadata: vector<u8>
    ) {
        let info = Info {
            owners,
            public_keys,
            //nonce,
            threshold,
            //metadata,
        };
        //let init_sequence_number = account::get_sequence_number(signer::address_of(msig));
        move_to(msig, SurgeWallet {
            info,
            txn_book: TxnBook {
                // min_sequence_number: init_sequence_number,
                // max_sequence_number: init_sequence_number,
                // tx_hashes: table_with_length::new(),
                pendings: table_with_length::new(),
            },
        });
    }

    /// Move the msig addresses from `pendings` to `msigs` in registry data
    /// when msig wallet is successfully registered.
    ///
    /// # Parameters
    /// * `msig`: signer object of the surge multi-sig wallet.
    /// * `owners`: owner address vector.
    /// * `msig_address`: address of msig wallet.
    ///
    /// # Emits
    /// * `RegisterEvent`
    fun add_to_registry(
        //msig: &signer, //anne: add this back if friend visibility not available
        owners: vector<address>,
        msig_address: address
    ) {
        user::register_msig(msig, &owners, msig_address)
    }

    //==============================================================================================
    // Helper functions
    //==============================================================================================


    //==============================================================================================
    // Getter functions
    //==============================================================================================

}