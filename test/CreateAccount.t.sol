// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test}               from "forge-std/Test.sol";
import {SailKernel, ISafeFactory, ISafe} from "../contracts/core/SailKernel.sol";
import {SailGovernance}     from "../contracts/governance/SailGovernance.sol";
import {TimelockDeployer}   from "./support/TimelockDeployer.sol";
import {SafeModuleEnabler}  from "../contracts/safe/SafeModuleEnabler.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {Create2}            from "@openzeppelin/contracts/utils/Create2.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Faithful Safe v1.4.1 harness
//
// Reproduces the parts of Safe v1.4.1 the onboarding fix depends on: a CREATE2
// proxy factory with deterministic address prediction, a Safe.setup that performs
// the `to`/`data` delegatecall, module enablement gated by msg.sender == address(this),
// and module execution. The security properties under test (delegatecall-target
// allowlisting, codehash identity, module-enabled gating) only have meaning against a
// faithful proxy, not a stub.
// ─────────────────────────────────────────────────────────────────────────────

bytes4 constant SAFE_SETUP_SELECTOR = 0xb63e800d; // setup(address[],uint256,address,bytes,address,address,uint256,address)

interface ISafeEnable {
    function enableModule(address module) external;
}

/// @dev Faithful Safe proxy: stores owners/threshold, runs the setup delegatecall, enforces
///      module-enable authorization, and records module executions.
contract FaithfulSafeProxy {
    address[] private _owners;
    uint256 public threshold;
    bool    private _setupDone;
    mapping(address => bool) private _modules;

    struct Rec { address to; uint256 value; bytes data; uint8 op; }
    Rec[] private _calls;
    bool public moduleCallSuccess = true;

    /// @dev Mirrors Safe v1.4.1 SafeProxy, which takes the singleton as a constructor arg —
    ///      so the deployed init code (creationCode ++ singleton) and thus the CREATE2 address
    ///      match what the kernel now predicts locally. The arg is intentionally NOT stored as
    ///      an immutable, so the runtime code (and codehash) stays singleton-independent, exactly
    ///      like a real SafeProxy (which holds the singleton in storage slot 0, not in code).
    constructor(address) {}

    receive() external payable {}

    function setup(
        address[] calldata owners_,
        uint256 threshold_,
        address to,
        bytes calldata data,
        address,            // fallbackHandler
        address,            // paymentToken
        uint256,            // payment
        address payable     // paymentReceiver
    ) external {
        require(!_setupDone, "already setup");
        _setupDone = true;
        for (uint256 i; i < owners_.length; i++) _owners.push(owners_[i]);
        threshold = threshold_;
        if (to != address(0)) {
            (bool ok, ) = to.delegatecall(data);
            require(ok, "setup delegatecall failed");
        }
    }

    function enableModule(address module) external {
        require(msg.sender == address(this), "GS031"); // mirrors Safe's authorized modifier
        _modules[module] = true;
    }

    function isModuleEnabled(address module) external view returns (bool) {
        return _modules[module];
    }

    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8 op)
        external
        returns (bool)
    {
        _calls.push(Rec(to, value, data, op));
        if (!moduleCallSuccess) return false;
        if (value > 0 && data.length == 0) {
            (bool ok, ) = payable(to).call{value: value}("");
            return ok;
        }
        return true;
    }

    function callCount() external view returns (uint256) { return _calls.length; }
    function setSuccess(bool s) external { moduleCallSuccess = s; }

    // Expose the (allowlisted) singleton and a finalized nonce so registerAccount's
    // singleton check and setup-not-finalized check pass for a faithfully set-up proxy.
    function masterCopy() external pure returns (address) { return address(0x5A1E); }
    function nonce() external pure returns (uint256) { return 1; }
    function checkSignatures(bytes32, bytes calldata, bytes calldata) external view {}
}

/// @dev Faithful Safe proxy factory: deterministic CREATE2 deploy + address prediction
///      matching Safe v1.4.1 semantics (salt = keccak256(keccak256(initializer), saltNonce)).
contract FaithfulSafeFactory is ISafeFactory {
    function createProxyWithNonce(address singleton, bytes calldata initializer, uint256 saltNonce)
        external
        override
        returns (address proxy)
    {
        bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), saltNonce));
        // Pass the singleton as a constructor arg so init code = creationCode ++ singleton,
        // exactly as Safe v1.4.1 deploys — keeps the CREATE2 address faithful.
        proxy = address(new FaithfulSafeProxy{salt: salt}(singleton));
        if (initializer.length > 0) {
            (bool ok, ) = proxy.call(initializer);
            require(ok, "proxy init failed");
        }
    }

    /// @inheritdoc ISafeFactory
    function proxyCreationCode() external pure override returns (bytes memory) {
        return type(FaithfulSafeProxy).creationCode;
    }

    /// @dev Test-side address predictor (not part of ISafeFactory). Matches the kernel's
    ///      local CREATE2 computation: init code = creationCode ++ uint256(uint160(singleton)).
    function calculateCreateProxyWithNonceAddress(address singleton, bytes calldata initializer, uint256 saltNonce)
        external
        view
        returns (address)
    {
        bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), saltNonce));
        bytes32 initCodeHash =
            keccak256(abi.encodePacked(type(FaithfulSafeProxy).creationCode, uint256(uint160(singleton))));
        return Create2.computeAddress(salt, initCodeHash, address(this));
    }
}

/// @dev Arbitrary non-Safe contract whose codehash is not allowlisted. Used to exercise the
///      codehash rejection path in `registerAccount` (self-registration).
contract MaliciousProxy {
    function isModuleEnabled(address) external pure returns (bool) { return true; }
    function execTransactionFromModule(address, uint256, bytes calldata, uint8) external pure returns (bool) { return true; }
}

/// @dev Factory that deploys a non-Safe proxy whose runtime codehash is not allowlisted, while
///      still satisfying the module-enabled check. Used to exercise createAccount's proxy-codehash
///      guard (the parity check with registerAccount).
contract RogueSafeFactory is ISafeFactory {
    function createProxyWithNonce(address, bytes calldata, uint256) external override returns (address proxy) {
        proxy = address(new MaliciousProxy());
    }

    function proxyCreationCode() external pure override returns (bytes memory) {
        return type(MaliciousProxy).creationCode;
    }
}

/// @dev Malicious setup helper for the stealth-pre-registration test. Delegatecalled during
///      Safe.setup (before any module is enabled), it tries to self-register the proxy.
contract StealthSetup {
    SailKernel immutable kernel;
    address immutable ps;
    address immutable mgr;

    constructor(SailKernel _kernel, address _ps, address _mgr) {
        kernel = _kernel; ps = _ps; mgr = _mgr;
    }

    function run() external {
        kernel.registerAccount(ps, mgr, address(0), address(0), block.timestamp + 1 days, "");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests (v2 spec: 10 cases)
// ─────────────────────────────────────────────────────────────────────────────

contract CreateAccountTest is Test {
    SailGovernance      gov;
    SailKernel          kernel;
    FaithfulSafeFactory factory;
    SafeModuleEnabler   moduleEnabler;

    address constant TEAM      = address(0x1111);
    address constant TREASURY  = address(0x2222);
    address constant EMERGENCY = address(0xEEEE);
    address constant SINGLETON = address(0x5A1E); // dummy; allowlisted, not dereferenced by mock
    address constant OWNER     = address(0x0E1E);

    address permSigner = address(0x5161);
    address manager    = address(0x6A11);

    bytes32 proxyCodehash;

    function setUp() public {
        gov           = new SailGovernance(TEAM, 0.001 ether, EMERGENCY, 0, TimelockDeployer.deploy(TEAM));
        // Deploy the enabler BEFORE the kernel so the kernel can pin its runtime codehash,
        // mirroring the launch deploy order.
        moduleEnabler = new SafeModuleEnabler();
        kernel        = new SailKernel(address(gov), TREASURY, address(moduleEnabler));
        factory       = new FaithfulSafeFactory();

        proxyCodehash = address(new FaithfulSafeProxy(SINGLETON)).codehash;

        _allowlist(abi.encodeCall(gov.setTrustedSafeFactory,        (address(factory), true)));
        _allowlist(abi.encodeCall(gov.setTrustedSafeSingleton,      (SINGLETON, true)));
        _allowlist(abi.encodeCall(gov.setTrustedModuleSetup,        (address(moduleEnabler), true)));
        _allowlist(abi.encodeCall(gov.setTrustedSafeProxyCodehash,  (proxyCodehash, true)));
    }

    // ── helpers ────────────────────────────────────────────────────────────────

    uint256 private _salt;
    function _allowlist(bytes memory data) internal {
        TimelockController tl = gov.timelock();
        bytes32 s = bytes32(_salt++);
        vm.prank(TEAM);
        tl.schedule(address(gov), 0, data, bytes32(0), s, 48 hours);
        vm.warp(block.timestamp + 48 hours + 1);
        vm.prank(TEAM);
        tl.execute(address(gov), 0, data, bytes32(0), s);
    }

    function _owners1() internal pure returns (address[] memory a) {
        a = new address[](1);
        a[0] = OWNER;
    }

    /// @dev Build a Safe v1.4.1 `setup` initializer enabling the kernel as a module via `to`.
    function _initializer(address to_) internal view returns (bytes memory) {
        bytes memory enableData = abi.encodeWithSelector(SafeModuleEnabler.enable.selector, address(kernel));
        return abi.encodeWithSelector(
            SAFE_SETUP_SELECTOR,
            _owners1(), uint256(1), to_, enableData,
            address(0), address(0), uint256(0), payable(address(0))
        );
    }

    function _boundSalt(uint256 saltNonce, address sender, address ps, address mgr, address fp)
        internal pure returns (uint256)
    {
        return uint256(keccak256(abi.encode(saltNonce, sender, ps, mgr, fp)));
    }

    function _create(address caller, uint256 saltNonce, address ps, address mgr, address fp)
        internal returns (address account)
    {
        vm.prank(caller);
        account = kernel.createAccount(
            address(factory), SINGLETON, _initializer(address(moduleEnabler)), saltNonce, ps, mgr, fp, address(0)
        );
    }

    /// @dev Deploy a faithful Safe directly via the factory, kernel module enabled.
    function _deploySafe(uint256 nonce) internal returns (FaithfulSafeProxy safe) {
        safe = FaithfulSafeProxy(payable(
            factory.createProxyWithNonce(SINGLETON, _initializer(address(moduleEnabler)), nonce)
        ));
    }

    // ── 1. Happy path ────────────────────────────────────────────────────────

    function test_CreateAccount_HappyPath() public {
        address predicted = factory.calculateCreateProxyWithNonceAddress(
            SINGLETON,
            _initializer(address(moduleEnabler)),
            _boundSalt(0, address(this), permSigner, manager, address(0))
        );

        address account = _create(address(this), 0, permSigner, manager, address(0));

        assertEq(account, predicted, "deployed at predicted address");
        assertTrue(kernel.registered(account));
        assertTrue(ISafe(account).isModuleEnabled(address(kernel)), "module enabled via setup delegatecall");
        (address ps, address mgr,,, bool active) = kernel.configs(account);
        assertEq(ps, permSigner);
        assertEq(mgr, manager);
        assertTrue(active);
    }

    // ── 2. Untrusted `to` → UntrustedModuleSetup ──────────────────────────────

    function test_CreateAccount_RevertsOnUntrustedModuleSetup() public {
        address rogue = address(0xBAD5E7);
        bytes memory init = _initializer(rogue); // `to` = non-allowlisted helper
        vm.expectRevert(abi.encodeWithSelector(SailKernel.UntrustedModuleSetup.selector, rogue));
        kernel.createAccount(address(factory), SINGLETON, init, 0, permSigner, manager, address(0), address(0));
    }

    // ── 3. Short initializer → InvalidInitializer ─────────────────────────────

    function test_CreateAccount_RevertsOnShortInitializer() public {
        vm.expectRevert(SailKernel.InvalidInitializer.selector);
        kernel.createAccount(address(factory), SINGLETON, hex"deadbeef", 0, permSigner, manager, address(0), address(0));
    }

    function test_CreateAccount_RevertsOnEmptyInitializer() public {
        vm.expectRevert(SailKernel.InvalidInitializer.selector);
        kernel.createAccount(address(factory), SINGLETON, "", 0, permSigner, manager, address(0), address(0));
    }

    // ── 4. Principal binding → different account address ──────────────────────

    function test_CreateAccount_PrincipalBinding_DifferentManagerDifferentAddress() public {
        address managerB = address(0x6B22);
        address accountA = _create(address(this), 0, permSigner, manager,  address(0));
        address accountB = _create(address(this), 0, permSigner, managerB, address(0));
        assertTrue(accountA != accountB, "different manager binds to different CREATE2 address");
    }

    // ── 5. Idempotency: pre-deployed proxy at computed address ────────────────

    function test_CreateAccount_Idempotency_PreDeployedProxy() public {
        bytes memory init = _initializer(address(moduleEnabler));
        uint256 bs = _boundSalt(0, address(this), permSigner, manager, address(0));
        address pre = factory.createProxyWithNonce(SINGLETON, init, bs);

        address account = _create(address(this), 0, permSigner, manager, address(0));

        assertEq(account, pre, "createAccount adopts the pre-deployed proxy");
        assertTrue(kernel.registered(account));
    }

    // ── 6. Front-run with same params: victim's call still proceeds ───────────

    function test_CreateAccount_FrontRunSameParams_VictimProceeds() public {
        // Third party reconstructs the kernel's exact initializer + boundSalt (victim =
        // address(this)) and deploys the proxy first.
        bytes memory init = _initializer(address(moduleEnabler));
        uint256 bs = _boundSalt(0, address(this), permSigner, manager, address(0));
        address frontrun = factory.createProxyWithNonce(SINGLETON, init, bs);

        address account = _create(address(this), 0, permSigner, manager, address(0));

        assertEq(account, frontrun, "victim registers the front-run-deployed proxy");
        assertTrue(kernel.registered(account));
    }

    // ── 7. registerAccount from non-Safe contract → UntrustedProxyCodehash ────

    function test_RegisterAccount_NonSafe_Reverts() public {
        MaliciousProxy mal = new MaliciousProxy();
        bytes32 ch = address(mal).codehash;
        vm.prank(address(mal));
        vm.expectRevert(abi.encodeWithSelector(SailKernel.UntrustedProxyCodehash.selector, ch));
        kernel.registerAccount(permSigner, manager, address(0), address(0), block.timestamp + 1 days, "");
    }

    function test_RegisterAccount_FromEOA_Reverts() public {
        address eoa = address(0xE0A);
        vm.prank(eoa);
        vm.expectRevert(abi.encodeWithSelector(SailKernel.UntrustedProxyCodehash.selector, eoa.codehash));
        kernel.registerAccount(permSigner, manager, address(0), address(0), block.timestamp + 1 days, "");
    }

    // ── 8. registerAccount from Safe with module NOT enabled → ModuleNotEnabled ─

    function test_RegisterAccount_ModuleNotEnabled_Reverts() public {
        // Deploy a proxy WITHOUT the setup delegatecall (to = address(0)), so no module enabled.
        bytes memory initNoModule = abi.encodeWithSelector(
            SAFE_SETUP_SELECTOR,
            _owners1(), uint256(1), address(0), bytes(""),
            address(0), address(0), uint256(0), payable(address(0))
        );
        FaithfulSafeProxy safe = FaithfulSafeProxy(payable(
            factory.createProxyWithNonce(SINGLETON, initNoModule, 999)
        ));
        assertFalse(safe.isModuleEnabled(address(kernel)));

        vm.prank(address(safe));
        vm.expectRevert(SailKernel.ModuleNotEnabled.selector);
        kernel.registerAccount(permSigner, manager, address(0), address(0), block.timestamp + 1 days, "");
    }

    // ── 9. registerAccount from Safe with module enabled + correct codehash ───

    function test_RegisterAccount_HappyPath() public {
        FaithfulSafeProxy safe = _deploySafe(42);
        assertTrue(safe.isModuleEnabled(address(kernel)));

        vm.prank(address(safe));
        kernel.registerAccount(permSigner, manager, address(0), address(0), block.timestamp + 1 days, "");

        assertTrue(kernel.registered(address(safe)));
        (address ps, address mgr,,,) = kernel.configs(address(safe));
        assertEq(ps, permSigner);
        assertEq(mgr, manager);
    }

    // ── 9b. createAccount enforces the proxy-codehash check (parity w/ registerAccount) ─

    /// @dev A trusted factory that yields a proxy with a non-allowlisted runtime codehash is
    ///      rejected, mirroring registerAccount. The happy-path test proves a legitimate proxy
    ///      (allowlisted codehash) still registers, so the guard is exercised on both sides.
    function test_CreateAccount_RevertsOnUntrustedProxyCodehash() public {
        RogueSafeFactory rogue = new RogueSafeFactory();
        _allowlist(abi.encodeCall(gov.setTrustedSafeFactory, (address(rogue), true)));

        bytes32 rogueCodehash = address(new MaliciousProxy()).codehash;
        vm.expectRevert(abi.encodeWithSelector(SailKernel.UntrustedProxyCodehash.selector, rogueCodehash));
        kernel.createAccount(
            address(rogue), SINGLETON, _initializer(address(moduleEnabler)), 1234, permSigner, manager, address(0), address(0)
        );
    }

    // ── 10. Stealth pre-registration during Safe.setup → ModuleNotEnabled ─────

    function test_RegisterAccount_StealthDuringSetup_Blocked() public {
        StealthSetup stealth = new StealthSetup(kernel, permSigner, manager);
        // Allowlist the stealth helper as a module-setup target by ADDRESS. Before the codehash pin
        // this passed the `to` address check and the stealth registration was then caught one layer
        // deeper by registerAccount's module-enabled guard (revert "proxy init failed"). With the
        // codehash pin, an address-allowlisted helper whose bytecode is NOT the immutable enabler is
        // rejected EARLIER — the stealth attack can no longer even reach Safe.setup. The deeper
        // module-enabled guard remains in code and is independently exercised by
        // test_RegisterAccount_ModuleNotEnabled_Reverts.
        _allowlist(abi.encodeCall(gov.setTrustedModuleSetup, (address(stealth), true)));

        bytes memory init = abi.encodeWithSelector(
            SAFE_SETUP_SELECTOR,
            _owners1(), uint256(1), address(stealth), abi.encodeWithSignature("run()"),
            address(0), address(0), uint256(0), payable(address(0))
        );

        // Codehash pin: stealth helper's codehash != pinned SafeModuleEnabler codehash → rejected up front.
        vm.expectRevert(abi.encodeWithSelector(SailKernel.UntrustedModuleSetupCodehash.selector, address(stealth)));
        kernel.createAccount(address(factory), SINGLETON, init, 7777, permSigner, manager, address(0), address(0));
    }

    // ── 11. Safe.setup helper codehash pin ─────────────────────────────────────

    /// @dev The kernel pins the codehash of the SafeModuleEnabler it was constructed with, so the
    ///      suite is internally consistent regardless of how the production constant is sourced.
    function test_KernelPinsTheDeployedEnablerCodehash() public view {
        assertEq(kernel.EXPECTED_SETUP_CODEHASH(), address(moduleEnabler).codehash);
    }

    /// @dev The genuine, address-allowlisted SafeModuleEnabler passes the pin: this is the same
    ///      target test_CreateAccount_HappyPath uses, so the happy path proves the pin is a no-op
    ///      for the legitimate helper. Asserted here too for an explicit happy-path anchor.
    function test_GenuineEnablerPassesPin() public {
        address account = _create(address(this), 100, permSigner, manager, address(0));
        assertTrue(kernel.registered(account));
        assertTrue(ISafe(account).isModuleEnabled(address(kernel)));
    }

    /// @dev A helper that is ADDRESS-allowlisted but whose runtime bytecode differs from the pinned
    ///      immutable enabler (a mutable/look-alike) is rejected by the codehash pin — the core
    ///      guarantee. The look-alike passes the address allowlist (so we reach the pin) but has a
    ///      different codehash, so createAccount reverts UntrustedModuleSetupCodehash.
    function test_RevertsOnMismatchedSetupCodehash() public {
        MaliciousProxy lookAlike = new MaliciousProxy(); // deployed code != SafeModuleEnabler
        assertTrue(address(lookAlike).codehash != kernel.EXPECTED_SETUP_CODEHASH());
        _allowlist(abi.encodeCall(gov.setTrustedModuleSetup, (address(lookAlike), true)));

        bytes memory init = _initializer(address(lookAlike));
        vm.expectRevert(abi.encodeWithSelector(SailKernel.UntrustedModuleSetupCodehash.selector, address(lookAlike)));
        kernel.createAccount(address(factory), SINGLETON, init, 222, permSigner, manager, address(0), address(0));
    }

    /// @dev The no-setup path (`to == address(0)`) must NOT be subject to the codehash pin — it is
    ///      gated on `setupTarget != address(0)` exactly like the address allowlist check. Here the
    ///      pin is correctly skipped; execution proceeds and fails later at ModuleNotEnabled (the
    ///      proxy has no module enabled because no setup delegatecall ran), proving the pin did not
    ///      fire on the zero target.
    function test_NoSetupPath_SkipsCodehashPin() public {
        bytes memory initNoSetup = abi.encodeWithSelector(
            SAFE_SETUP_SELECTOR,
            _owners1(), uint256(1), address(0), bytes(""),
            address(0), address(0), uint256(0), payable(address(0))
        );
        vm.expectRevert(SailKernel.ModuleNotEnabled.selector);
        kernel.createAccount(address(factory), SINGLETON, initNoSetup, 333, permSigner, manager, address(0), address(0));
    }

    // ── 11. Safe.setup deployment-payment fields are rejected ─────────────────
    // createAccount must not deploy a Safe whose setup() carries a non-zero payment field, which
    // would transfer funds out of the freshly deployed proxy during deployment.

    /// @dev Build an initializer enabling the kernel module, with explicit setup() payment fields.
    function _initializerPay(address payToken, uint256 pay, address payReceiver)
        internal view returns (bytes memory)
    {
        bytes memory enableData = abi.encodeWithSelector(SafeModuleEnabler.enable.selector, address(kernel));
        return abi.encodeWithSelector(
            SAFE_SETUP_SELECTOR,
            _owners1(), uint256(1), address(moduleEnabler), enableData,
            address(0), payToken, pay, payable(payReceiver)
        );
    }

    function test_CreateAccount_RevertsOnNonZeroPaymentToken() public {
        bytes memory init = _initializerPay(address(0xC0FFEE), 0, address(0));
        vm.expectRevert(SailKernel.SetupPaymentNotAllowed.selector);
        kernel.createAccount(address(factory), SINGLETON, init, 0, permSigner, manager, address(0), address(0));
    }

    function test_CreateAccount_RevertsOnNonZeroPayment() public {
        bytes memory init = _initializerPay(address(0), 1, address(0));
        vm.expectRevert(SailKernel.SetupPaymentNotAllowed.selector);
        kernel.createAccount(address(factory), SINGLETON, init, 0, permSigner, manager, address(0), address(0));
    }

    function test_CreateAccount_RevertsOnNonZeroPaymentReceiver() public {
        bytes memory init = _initializerPay(address(0), 0, address(0xBEEF));
        vm.expectRevert(SailKernel.SetupPaymentNotAllowed.selector);
        kernel.createAccount(address(factory), SINGLETON, init, 0, permSigner, manager, address(0), address(0));
    }

    /// @dev All three payment fields zero (the only shape honest onboarding produces) is a no-op
    ///      for the guard: deployment + registration proceed exactly as before.
    function test_CreateAccount_ZeroPaymentFields_Succeeds() public {
        bytes memory init = _initializerPay(address(0), 0, address(0));
        address account = kernel.createAccount(
            address(factory), SINGLETON, init, 0, permSigner, manager, address(0), address(0)
        );
        assertTrue(kernel.registered(account), "zero-payment initializer registers normally");
        assertTrue(ISafe(account).isModuleEnabled(address(kernel)));
    }

    /// @dev The guard is independent of the setup `to` target: a no-setup (to == 0) initializer
    ///      carrying a non-zero payment field is still rejected.
    function test_CreateAccount_NoSetupPath_RejectsPayment() public {
        bytes memory init = abi.encodeWithSelector(
            SAFE_SETUP_SELECTOR,
            _owners1(), uint256(1), address(0), bytes(""),
            address(0), address(0), uint256(1), payable(address(0))
        );
        vm.expectRevert(SailKernel.SetupPaymentNotAllowed.selector);
        kernel.createAccount(address(factory), SINGLETON, init, 444, permSigner, manager, address(0), address(0));
    }
}
