// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {SailKernel}       from "../contracts/core/SailKernel.sol";
import {SailGovernance}   from "../contracts/governance/SailGovernance.sol";
import {TimelockDeployer} from "./support/TimelockDeployer.sol";

/// @dev Configurable Safe-proxy stand-in for the registration-auth tests.
///      Stores its singleton in regular storage (not immutable / not in code), so every instance
///      shares one runtime codehash — exactly like a real SafeProxy — letting a single codehash
///      seed cover the trusted- and untrusted-singleton instances alike. `nonce` and module-enabled
///      are settable so a test can reproduce the setup-time (nonce == 0) shape.
///
///      checkSignatures faithfully mirrors Safe-core for a single-owner, threshold-1 Safe: it
///      ECDSA-recovers `dataHash` and reverts unless the signer is the configured owner — so the
///      owner-signature gate is exercised for real (valid sig succeeds; forged-nonce-without-sig
///      and non-owner sig revert).
contract ConfigurableSafe {
    address private _singleton;
    uint256 private _nonce = 1;          // a finalized Safe has nonce >= 1
    bool    private _moduleEnabled = true;
    address public  owner;               // single owner whose signature authorises registration

    constructor(address singleton_, address owner_) { _singleton = singleton_; owner = owner_; }

    function masterCopy() external view returns (address) { return _singleton; }
    function nonce() external view returns (uint256) { return _nonce; }
    function isModuleEnabled(address) external view returns (bool) { return _moduleEnabled; }
    function setNonce(uint256 n) external { _nonce = n; }
    function setModuleEnabled(bool v) external { _moduleEnabled = v; }

    /// @dev Mirrors Safe-core checkSignatures for one owner / threshold 1: revert unless `signatures`
    ///      is a valid ECDSA signature over `dataHash` by `owner`. Reverts (like the real Safe) rather
    ///      than returning a flag.
    function checkSignatures(bytes32 dataHash, bytes calldata, bytes calldata signatures) external view {
        require(signatures.length >= 65, "GS020");
        bytes32 r;
        bytes32 s;
        uint8   v;
        assembly {
            r := calldataload(signatures.offset)
            s := calldataload(add(signatures.offset, 0x20))
            v := byte(0, calldataload(add(signatures.offset, 0x40)))
        }
        address rec = ecrecover(dataHash, v, r, s);
        require(rec != address(0) && rec == owner, "GS026");
    }

    /// @dev Forward `data` to `kernel`, appending the original caller's 20 bytes — reproducing a
    ///      Safe FallbackManager relay when fallbackHandler == kernel.
    function relayWithTrailingBytes(address kernel, bytes calldata data, address originalCaller)
        external
        returns (bool ok, bytes memory ret)
    {
        (ok, ret) = kernel.call(abi.encodePacked(data, bytes20(originalCaller)));
    }

    /// @dev Forward `data` to `kernel` verbatim (exact length) — a legitimate direct Safe call.
    function relayExact(address kernel, bytes calldata data) external returns (bool ok, bytes memory ret) {
        (ok, ret) = kernel.call(data);
    }
}

contract RegistrationAuthTest is Test {
    SailKernel     kernel;
    SailGovernance gov;

    address constant TEAM      = address(0x1111);
    address constant TREASURY  = address(0x2222);
    address constant EMERGENCY = address(0xEEEE);

    address constant TRUSTED_SINGLETON   = address(0x600D);
    address constant UNTRUSTED_SINGLETON = address(0x0BAD);

    uint256 constant OWNER_KEY    = 0xB00C;
    uint256 constant ATTACKER_KEY = 0xBAD5;
    address owner;

    address permSigner = address(0x5161);
    address manager    = address(0x6A11);

    function setUp() public {
        owner  = vm.addr(OWNER_KEY);
        gov    = new SailGovernance(TEAM, 0.001 ether, EMERGENCY, 0, TimelockDeployer.deploy(TEAM));
        kernel = new SailKernel(address(gov), TREASURY, address(0));

        // One codehash seed covers every ConfigurableSafe instance.
        ConfigurableSafe seed = new ConfigurableSafe(TRUSTED_SINGLETON, owner);
        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeProxyCodehash(address(seed).codehash, true);
        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeSingleton(TRUSTED_SINGLETON, true);
    }

    function _newSafe(address singleton) internal returns (ConfigurableSafe s) {
        s = new ConfigurableSafe(singleton, owner);
    }

    /// @dev Build an owner signature over the RegisterAccount digest for `account`, signed with `key`.
    function _ownerSig(address account, address fp, address fa, uint256 deadline, uint256 key)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(abi.encode(
            kernel.REGISTER_ACCOUNT_TYPEHASH(), account, permSigner, manager, fp, fa, deadline
        ));
        bytes32 digest = kernel.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _register(ConfigurableSafe safe, address fp, address fa) internal {
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = _ownerSig(address(safe), fp, fa, deadline, OWNER_KEY);
        vm.prank(address(safe));
        kernel.registerAccount(permSigner, manager, fp, fa, deadline, sig);
    }

    // ── owner-signature gate ─────────────────────────────────────────────────────

    /// A valid owner signature registers the account.
    function test_OwnerSignature_Valid_Registers() public {
        ConfigurableSafe safe = _newSafe(TRUSTED_SINGLETON);
        _register(safe, address(0), address(0));
        assertTrue(kernel.registered(address(safe)));
        (address ps, address mgr,,,) = kernel.configs(address(safe));
        assertEq(ps, permSigner);
        assertEq(mgr, manager);
    }

    /// THE case the old nonce-only guard let through: a setup helper forges nonce -> 1 (here the
    /// mock simply reports nonce 1) and calls registerAccount WITHOUT a valid owner signature.
    /// Now rejected — the owner-sig is unforgeable by a helper holding no owner keys.
    function test_ForgedNonce_NoOwnerSignature_Rejected() public {
        ConfigurableSafe safe = _newSafe(TRUSTED_SINGLETON); // nonce == 1, module on, trusted singleton
        vm.prank(address(safe));
        vm.expectRevert(bytes("GS020")); // checkSignatures: empty/short signature
        kernel.registerAccount(permSigner, manager, address(0), address(0), block.timestamp + 1 days, "");
        assertFalse(kernel.registered(address(safe)));
    }

    /// A signature from a non-owner key is rejected by the Safe's owner check.
    function test_NonOwnerSignature_Rejected() public {
        ConfigurableSafe safe = _newSafe(TRUSTED_SINGLETON);
        uint256 deadline = block.timestamp + 1 days;
        bytes memory badSig = _ownerSig(address(safe), address(0), address(0), deadline, ATTACKER_KEY);
        vm.prank(address(safe));
        vm.expectRevert(bytes("GS026")); // checkSignatures: recovered signer is not an owner
        kernel.registerAccount(permSigner, manager, address(0), address(0), deadline, badSig);
        assertFalse(kernel.registered(address(safe)));
    }

    /// An `ownerSig` carrying a Safe approved-hash (v == 1) entry must be rejected outright. Inside
    /// Safe-core `checkSignatures` msg.sender would be the kernel, so a v==1 entry encoding the kernel
    /// as "owner" would authorise registration with no genuine owner key — the kernel forbids it.
    function test_ApprovedHashSignature_Rejected() public {
        ConfigurableSafe safe = _newSafe(TRUSTED_SINGLETON);
        // One 65-byte entry: r = some address, s = 0, v = 1 (the approved-hash shortcut).
        bytes memory v1Sig = abi.encodePacked(bytes32(uint256(uint160(address(kernel)))), bytes32(0), uint8(1));
        vm.prank(address(safe));
        vm.expectRevert(SailKernel.ApprovedHashSignatureNotAllowed.selector);
        kernel.registerAccount(permSigner, manager, address(0), address(0), block.timestamp + 1 days, v1Sig);
        assertFalse(kernel.registered(address(safe)));
    }

    /// Defense-in-depth: nonce == 0 is rejected before the owner-sig is even checked.
    function test_NonceZero_DefenseInDepth_Rejected() public {
        ConfigurableSafe safe = _newSafe(TRUSTED_SINGLETON);
        safe.setNonce(0);
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = _ownerSig(address(safe), address(0), address(0), deadline, OWNER_KEY); // even a valid sig
        vm.prank(address(safe));
        vm.expectRevert(SailKernel.SetupNotFinalized.selector);
        kernel.registerAccount(permSigner, manager, address(0), address(0), deadline, sig);
    }

    /// A registration whose deadline has passed is rejected.
    function test_DeadlineExpired_Rejected() public {
        ConfigurableSafe safe = _newSafe(TRUSTED_SINGLETON);
        vm.warp(1_000_000);
        uint256 deadline = block.timestamp - 1;
        bytes memory sig = _ownerSig(address(safe), address(0), address(0), deadline, OWNER_KEY);
        vm.prank(address(safe));
        vm.expectRevert(abi.encodeWithSelector(SailKernel.DeadlineExpired.selector, deadline, block.timestamp));
        kernel.registerAccount(permSigner, manager, address(0), address(0), deadline, sig);
    }

    // ── trusted-singleton check (unchanged; runs before the owner-sig) ────────────

    function test_UntrustedSingleton_Rejected() public {
        ConfigurableSafe safe = _newSafe(UNTRUSTED_SINGLETON);
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = _ownerSig(address(safe), address(0), address(0), deadline, OWNER_KEY);
        vm.prank(address(safe));
        vm.expectRevert(abi.encodeWithSelector(SailKernel.UntrustedSingleton.selector, UNTRUSTED_SINGLETON));
        kernel.registerAccount(permSigner, manager, address(0), address(0), deadline, sig);
    }

    function test_TrustedSingleton_Registers() public {
        ConfigurableSafe safe = _newSafe(TRUSTED_SINGLETON);
        _register(safe, address(0), address(0));
        assertTrue(kernel.registered(address(safe)));
    }

    // ── fallback relay ────────────────────────────────────────────────────────────

    /// registerAccount no longer carries an exact-length guard (its owner-sig arg is dynamic).
    /// The owner-signature requirement itself closes the fallback vector: a relay sets
    /// msg.sender == Safe but cannot supply the owners' signature, so registration is rejected.
    function test_RegisterAccount_FallbackRelay_NoOwnerSignature_Rejected() public {
        ConfigurableSafe safe = _newSafe(TRUSTED_SINGLETON);
        uint256 deadline = block.timestamp + 1 days;
        // Attacker-controlled (non-owner) signature, delivered via the Safe fallback relay (+20 bytes).
        bytes memory badSig = _ownerSig(address(safe), address(0), address(0), deadline, ATTACKER_KEY);
        bytes memory data = abi.encodeWithSelector(
            kernel.registerAccount.selector, permSigner, manager, address(0), address(0), deadline, badSig
        );
        (bool ok,) = safe.relayWithTrailingBytes(address(kernel), data, address(0xA77ACC));
        assertFalse(ok, "fallback relay without a valid owner signature must revert");
        assertFalse(kernel.registered(address(safe)));
    }

    /// setManager keeps its exact-length guard: a fallback-shaped call is rejected; exact works.
    function test_SetManager_FallbackShape_Rejected() public {
        ConfigurableSafe safe = _newSafe(TRUSTED_SINGLETON);
        _register(safe, address(0), address(0));

        bytes memory data = abi.encodeWithSelector(kernel.setManager.selector, address(0xBEEF));
        (bool ok, bytes memory ret) = safe.relayWithTrailingBytes(address(kernel), data, address(0xA77ACC));
        assertFalse(ok);
        assertEq(bytes4(ret), SailKernel.UnexpectedCalldataLength.selector);
        assertEq(kernel.getManager(address(safe)), manager, "manager must be unchanged");

        (bool ok2,) = safe.relayExact(address(kernel), data);
        assertTrue(ok2);
        assertEq(kernel.getManager(address(safe)), address(0xBEEF));
    }

    /// collectFees keeps its exact-length guard: a fallback-shaped call is rejected by the length
    /// guard (first check); an exact-length call clears it and reverts later for a different reason.
    function test_CollectFees_FallbackShape_Rejected() public {
        ConfigurableSafe safe = _newSafe(TRUSTED_SINGLETON);
        _register(safe, address(0), address(0));

        bytes memory data = abi.encodeWithSelector(
            kernel.collectFees.selector, address(safe), uint256(1), uint256(1), address(0)
        );
        (bool ok, bytes memory ret) = safe.relayWithTrailingBytes(address(kernel), data, address(0xA77ACC));
        assertFalse(ok);
        assertEq(bytes4(ret), SailKernel.UnexpectedCalldataLength.selector);

        (bool ok2, bytes memory ret2) = safe.relayExact(address(kernel), data);
        assertFalse(ok2);
        assertTrue(bytes4(ret2) != SailKernel.UnexpectedCalldataLength.selector, "must pass length guard");
        assertEq(bytes4(ret2), SailKernel.FeePolicyNotSet.selector);
    }
}
