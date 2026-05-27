// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test}               from "forge-std/Test.sol";
import {SailKernel, ISafeFactory, ISafe} from "../contracts/core/SailKernel.sol";
import {SailGovernance}     from "../contracts/governance/SailGovernance.sol";
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
}

/// @dev Faithful Safe proxy factory: deterministic CREATE2 deploy + address prediction
///      matching Safe v1.4.1 semantics (salt = keccak256(keccak256(initializer), saltNonce)).
contract FaithfulSafeFactory is ISafeFactory {
    function createProxyWithNonce(address, bytes calldata initializer, uint256 saltNonce)
        external
        override
        returns (address proxy)
    {
        bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), saltNonce));
        proxy = address(new FaithfulSafeProxy{salt: salt}());
        if (initializer.length > 0) {
            (bool ok, ) = proxy.call(initializer);
            require(ok, "proxy init failed");
        }
    }

    function calculateCreateProxyWithNonceAddress(address, bytes calldata initializer, uint256 saltNonce)
        external
        view
        override
        returns (address)
    {
        bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), saltNonce));
        return Create2.computeAddress(salt, keccak256(type(FaithfulSafeProxy).creationCode), address(this));
    }
}

/// @dev Arbitrary non-Safe contract whose codehash is not allowlisted. Used to exercise the
///      codehash rejection path in `registerAccount` (finding #4a self-registration).
contract MaliciousProxy {
    function isModuleEnabled(address) external pure returns (bool) { return true; }
    function execTransactionFromModule(address, uint256, bytes calldata, uint8) external pure returns (bool) { return true; }
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
        kernel.registerAccount(ps, mgr, address(0), address(0));
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
        gov           = new SailGovernance(TEAM, 0.001 ether, EMERGENCY, 0);
        kernel        = new SailKernel(address(gov), TREASURY);
        factory       = new FaithfulSafeFactory();
        moduleEnabler = new SafeModuleEnabler();

        proxyCodehash = address(new FaithfulSafeProxy()).codehash;

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
        kernel.registerAccount(permSigner, manager, address(0), address(0));
    }

    function test_RegisterAccount_FromEOA_Reverts() public {
        address eoa = address(0xE0A);
        vm.prank(eoa);
        vm.expectRevert(abi.encodeWithSelector(SailKernel.UntrustedProxyCodehash.selector, eoa.codehash));
        kernel.registerAccount(permSigner, manager, address(0), address(0));
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
        kernel.registerAccount(permSigner, manager, address(0), address(0));
    }

    // ── 9. registerAccount from Safe with module enabled + correct codehash ───

    function test_RegisterAccount_HappyPath() public {
        FaithfulSafeProxy safe = _deploySafe(42);
        assertTrue(safe.isModuleEnabled(address(kernel)));

        vm.prank(address(safe));
        kernel.registerAccount(permSigner, manager, address(0), address(0));

        assertTrue(kernel.registered(address(safe)));
        (address ps, address mgr,,,) = kernel.configs(address(safe));
        assertEq(ps, permSigner);
        assertEq(mgr, manager);
    }

    // ── 10. Stealth pre-registration during Safe.setup → ModuleNotEnabled ─────

    function test_RegisterAccount_StealthDuringSetup_Blocked() public {
        StealthSetup stealth = new StealthSetup(kernel, permSigner, manager);
        // Allowlist the stealth helper as a module-setup target so the createAccount `to`
        // check passes and we actually exercise registerAccount's module-enabled guard —
        // the real defense for finding #4b.
        _allowlist(abi.encodeCall(gov.setTrustedModuleSetup, (address(stealth), true)));

        bytes memory init = abi.encodeWithSelector(
            SAFE_SETUP_SELECTOR,
            _owners1(), uint256(1), address(stealth), abi.encodeWithSignature("run()"),
            address(0), address(0), uint256(0), payable(address(0))
        );

        // The stealth helper calls registerAccount during setup, before the module is enabled,
        // so it reverts ModuleNotEnabled → setup's require(ok) fails → factory's require fails.
        vm.expectRevert(bytes("proxy init failed"));
        kernel.createAccount(address(factory), SINGLETON, init, 7777, permSigner, manager, address(0), address(0));
    }
}
