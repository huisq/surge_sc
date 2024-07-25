module surge::user {
    use moveos_std::event;
    use std::vector;
    use moveos_std::signer;

    //==============================================================================================
    // Errors
    //==============================================================================================

    /// This module keeps track of the msig addresses owned by an owner address.
    /// The data is published under each address's resource.
    ///

    /// Error code for duplicate address registration.
    const EADDRESS_ALREADY_REGISTERED: u64 = 1;

    /// Error code for the user request updates on non-initialized data
    /// which is not registered previously.
    const EADDRESS_NOT_REGISTRERED: u64 = 2;

    /// Error code for user unregistering a msig wallet which is not
    /// registered previously.
    const EMSIG_NOT_REGISTERED: u64 = 3;

    /// Error code for user has rotated their public key. In the current
    /// implementation, since the key rotation interface in Aptos account.move
    /// is not finalized, client side key rotation is not supported.
    ///
    /// The key rotation feature (multi-sig wallet permission change & multi-sig
    /// wallet key rotation according to single wallet key rotation) will be
    /// supported shortly.
    const EPUBLIC_KEY_ROTATED: u64 = 4;

    /// Error code for msig already exist
    const EMISG_ALREADY_EXIST: u64 = 5;

    //==============================================================================================
    // Constants
    //==============================================================================================

    const OP_MSIG_INIT: u8 = 1;
    const OP_MSIG_PENDING: u8 = 2;
    const OP_MSIG_CONFIRM: u8 = 3;

    //==============================================================================================
    // Structs
    //==============================================================================================

    /// The following data is stored on chain under the account resource:
    ///     1. Public Key: The public key when user registers his account into
    ///             Surge. The public key is used to check whether
    ///             user has conducted a key rotation.
    ///     2. Pendings: msig wallet addresses that are in pending
    ///             creation status. The address will be cleared if the wallet
    ///             is successfully registered in surge module.
    ///     3. misgs: msig wallet addresses that has already been
    ///             registered.
    struct OwnerMsigs has key {
        public_key: vector<u8>,
        // we use TableMap, beacuse anyone can add a new msig into others pending list.
        // if we use vector<address> here, it may have performance issues.
        // the `bool` just used to hold the Value position of table, it is always true.
        pendings: TableMap<address, bool>, 
        //anne: TableMap is forked from Apto's table_with_length, which is a iteratable table with more efficient storage than vector for large scale
        //need to discuss alternative on Rooch
        owned_msigs: TableMap<address, bool>,
    }

    //==============================================================================================
    // Events
    //==============================================================================================

    struct OwnerMigsChangeEvent has store, drop {
        public_key: vector<u8>,
        msig: address,
        op_type: u8,
        pendings_length: u64,
        owned_msigs_length: u64,
    }

    //==============================================================================================
    // Entry Functions
    //==============================================================================================

    /// Publish the OwnerMsigs under the user's account resource.
    /// The the function shall be called only once when user is first interacting
    /// with msig wallet modules. The user public key is required for the
    /// registration, used for tracking user's key rotation.
    ///
    /// # Parameters
    /// * `s`: The signer object from the single signed wallet.
    /// * `public_key`: User's public key.
    ///
    /// # Emits
    /// * `RegisterEvent`: `OwnerMsigs` struct that holds addresses owned by
    ///         the signer.
    ///
    /// # Aborts
    /// * `EADDRESS_ALREADY_REGISTERED`: User has registered before;
    /// * `EPUBLIC_KEY_ROTATED`: The input public key does not match the auth
    ///         key in `account.move`.
    public entry fun register( 
        s: &signer,
        public_key: vector<u8>,
    ) {
        let signer_address = signer::address_of(s);

        // Check whether user has registered before.
        assert!(!is_registered(signer_address), EADDRESS_ALREADY_REGISTERED);

        // Check whether the input public key matches user's authentication key.
        assert!(verify_public_key(signer_address, public_key), EPUBLIC_KEY_ROTATED); //anne: not sure if rooch can do this

        // Construct OwnerMsigs and write to account resource
        let msigs = OwnerMsigs {
            public_key,
            pendings: table_map::create(),
            owned_msigs: table_map::create()
        };
        move_to(s, msigs);

        // The explicit move operation here avoids an unnecessary copy of the complicated
        // data structure OwnerMsigs.
        event::emit(OwnerMigsChangeEvent {
            public_key,
            msig: @0x0,
            op_type: OP_MSIG_INIT,
            pendings_length: 0,
            owned_msigs_length: 0,
        });
    }

    //==============================================================================================
    // Internal functions
    //==============================================================================================

    /// Register the multi-sig wallet to the owners. (Only called by surge.move) //anne: friend/package visibility in Rooch?
    ///
    /// Add the msig address to `pending` under each addresses' `OwnerMsigs` structure.
    ///
    /// # Parameters
    /// * `owners`: list of addresses of the multi-sig owners.
    /// * `msig_addr`: the address of the msig wallet multi-sig wallet.
    /// * `pending`: Whether the request is from pending creation or account
    ///         that have been previously registered.
    ///
    /// # Emits
    /// * `RegisterEvent` if the msig_addr is added in owner resource.
    public(friend) fun register_msig(
        //msig: &signer, //anne: add this back if friend visibility not available
        owners: &vector<address>,
        msig_addr: address,
    ) {
        let i = 0;
        let len = vector::length<address>(owners);
        while (i < len) {
            let owner = *vector::borrow(owners, i);
            add_pending_msig(owner, msig_addr);
            i = i + 1
        }
    }

    /// Add msig address to owner's msig wallet address list, which is
    /// `OwnerMsigs.msigs`
    ///
    /// # Parameters
    /// * `owner`: owner address.
    /// * `msig`: msig wallet address.
    ///
    /// # Aborts
    /// * `EADDRESS_NOT_REGISTRERED`: the owner address has not registered.
    /// * `EMISG_ALREADY_EXIST`: the msig wallet has already been registered in user's OwnerMsigs.pending.
    ///
    /// # Emits
    /// * `OwnerMigsChangeEvent` :OP_MSIG_PENDING
    fun add_pending_msig(
        owner: address,
        msig: address,
    ) {
        // Get the OwnerMsigs from account resource
        assert!(exists<OwnerMsigs>(owner), EADDRESS_NOT_REGISTRERED);
        let owner_msig = borrow_global_mut<OwnerMsigs>(owner);
        assert!(!table_map::contains_key(&owner_msig.msigs, &msig), EMISG_ALREADY_EXIST);
        let pendings = &mut owner_msig.pendings;
        // If the msig address is not registered in pendings, add to pendings
        // and emit the event.
        table_map::add(pendings, msig, true);
        emit_register_event(owner, msig, OP_MSIG_PENDING);
    }

    /// Accepts msig co-owner invitation (from pending invite), 
    /// called from surge.move by user, move msig from pending to owned_msigs
    ///
    /// # Parameters
    /// * `owner`: owner address.
    /// * `msig`: msig wallet address to be added.
    ///
    /// # Aborts
    /// * `EADDRESS_NOT_REGISTRERED`: Owner has not registered.
    public(friend) fun confirm_pending_msig(
        owner: address,
        msig: address,
    ) {
        assert!(exists<OwnerMsigs>(owner), EADDRESS_NOT_REGISTRERED);
        let pendings = &mut borrow_global_mut<OwnerMsigs>(owner).pendings;
        assert!(table_map::contains_key(pendings, &msig), EMSIG_NOT_REGISTERED);
        table_map::remove(pendings, &msig);
        add_confirmed_msigs(owner, msig);
    }

    /// Add msig address to owner's msig wallet address list, which is `OwnerMsigs.msigs`
    /// called by user::confirm_pending_msig
    ///
    /// # Parameters
    /// * `owner`: owner address.
    /// * `msig`: msig wallet address.
    ///
    /// # Aborts
    /// * `EADDRESS_NOT_REGISTRERED`: the owner address has not registered.
    ///
    /// # Emits
    /// * `OwnerMigsChangeEvent` :OP_MSIG_CONFIRM
    fun add_confirmed_msigs(
        owner: address,
        msig: address,
    ) {
        // Get the OwnerMsigs from the account resource
        assert!(exists<OwnerMsigs>(owner), EADDRESS_NOT_REGISTRERED);
        let owned_msigs = &mut borrow_global_mut<OwnerMsigs>(owner).owned_msigs;
        assert!(!table_map::contains_key(owned_msigs, &msig), EMISG_ALREADY_EXIST);
        // If msig is not previously registered, add it to account owned msigs.
        table_map::add(owned_msigs, msig, true);
        emit_register_event(owner, msig, OP_MSIG_CONFIRM);
    }

    //==============================================================================================
    // Helper functions
    //==============================================================================================

    /// Emit an event when there is a change for user owned msig wallets.
    ///
    /// # Parameters
    /// * `owner`: owner address to emit the registration event.
    ///
    /// # Emits
    /// * ``OwnerMigsChangeEvent` 
    fun emit_register_event(
        owner: address, msig: address, op_type: u8
    ) {
        let owner_msig = borrow_global<OwnerMsigs>(owner);
        event::emit(
            OwnerMigsChangeEvent {
                public_key: owner_msig.public_key,
                msig,
                op_type,
                pendings_length: table_map::length(&owner_msig.pendings),
                msigs_length: table_map::length(&owner_msig.msigs),
            }
        )
    }

    /// Return whether the account address has previously been registered within
    /// the move module.
    ///
    /// # Parameters
    /// * `owner`: address
    ///
    /// # Returns
    /// * `bool`: whether the owner has been registered before.
    fun is_registered(
        owner: address,
    ): bool {
        exists<OwnerMsigs>(owner)
    }

    //==============================================================================================
    // Getter functions
    //==============================================================================================
    

}