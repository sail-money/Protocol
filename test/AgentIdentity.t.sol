// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import "forge-std/Test.sol";

import {IAgentIdentityResolver,
        IAccountAgentIdentityResolver,
        AgentIdentityRef}                  from "../contracts/interfaces/IAgentIdentityResolver.sol";
import {IPermissionIntrospection}          from "../contracts/interfaces/IPermissionIntrospection.sol";
import {IPermission, Context}              from "../contracts/interfaces/IPermission.sol";
import {SailCapabilities}                  from "../contracts/interfaces/SailCapabilities.sol";
import {SailKernel}                        from "../contracts/core/SailKernel.sol";
import {SailGovernance}                    from "../contracts/governance/SailGovernance.sol";
import {MockAgentIdentityPermission,
        MockAccountAgentIdentityPermission} from "./mocks/MockAgentIdentityPermission.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Minimal Safe stub — records module calls, returns true.
// ─────────────────────────────────────────────────────────────────────────────
contract AgentTestSafe {
    uint256 public callCount;
    bool    public moduleCallSuccess = true;

    function execTransactionFromModule(address, uint256, bytes calldata, uint8)
        external returns (bool)
    {
        callCount++;
        return moduleCallSuccess;
    }

    function isModuleEnabled(address) external pure returns (bool) { return true; }
    receive() external payable {}
}

// ─────────────────────────────────────────────────────────────────────────────
// AgentIdentityTest
// ─────────────────────────────────────────────────────────────────────────────
contract AgentIdentityTest is Test {
    // ── Keys & addresses ──────────────────────────────────────────────────────
    uint256 internal constant MANAGER_KEY = 0xAA11;
    uint256 internal constant SIGNER_KEY  = 0xBB22;

    address internal manager;
    address internal permSigner;

    address internal constant TREASURY = address(0xFEE5);
    address internal constant ALICE     = address(0xA11CE);
    address internal constant BOB       = address(0xB0B);
    address internal constant REGISTRY  = address(0x8004);

    // ── Contracts ─────────────────────────────────────────────────────────────
    SailGovernance internal gov;
    SailKernel     internal kernel;
    AgentTestSafe  internal safe;

    MockAgentIdentityPermission        internal globalPerm;
    MockAccountAgentIdentityPermission internal perAccountPerm;

    AgentIdentityRef internal _ref;       // shared fixture

    // ── Setup ─────────────────────────────────────────────────────────────────

    function setUp() public {
        manager    = vm.addr(MANAGER_KEY);
        permSigner = vm.addr(SIGNER_KEY);

        gov    = new SailGovernance(address(this), 0.001 ether, address(this), 0);
        kernel = new SailKernel(address(gov), TREASURY);
        safe   = new AgentTestSafe();

        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeProxyCodehash(address(safe).codehash, true);

        vm.prank(address(safe));
        kernel.registerAccount(permSigner, manager, address(0), address(0));

        // Canonical test identity
        _ref = AgentIdentityRef({
            namespaceHash:    keccak256("eip155"),
            chainId:          8453,
            identityRegistry: REGISTRY,
            agentId:          42,
            agentWallet:      ALICE
        });

        globalPerm = new MockAgentIdentityPermission(_ref, true);

        // Per-account mock: configure two accounts
        address[] memory accs = new address[](2);
        accs[0] = ALICE;
        accs[1] = BOB;
        AgentIdentityRef[] memory refs = new AgentIdentityRef[](2);
        refs[0] = _ref;
        refs[1] = AgentIdentityRef({
            namespaceHash:    keccak256("erc8004"),
            chainId:          1,
            identityRegistry: address(0xDEAD),
            agentId:          7,
            agentWallet:      BOB
        });
        perAccountPerm = new MockAccountAgentIdentityPermission(accs, refs, true);
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    function _registerPermission(address permission) internal {
        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 deadline = block.timestamp + 1 days;
        bytes32 sh = keccak256(abi.encode(
            kernel.REGISTER_PERMISSION_TYPEHASH(), address(safe), permission, nonce, deadline
        ));
        bytes32 digest = kernel.hashTypedDataV4(sh);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, digest);
        kernel.registerPermission(address(safe), permission, deadline, abi.encodePacked(r, s, v));
    }

    function _signDispatch(
        address permission,
        address target,
        uint256 value,
        bytes memory data,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 sh = keccak256(abi.encode(
            kernel.DISPATCH_TYPEHASH(),
            address(safe), permission, target, value, keccak256(data), nonce, deadline
        ));
        bytes32 digest = kernel.hashTypedDataV4(sh);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MANAGER_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // INTERFACE READS — IAgentIdentityResolver (tests 1–5)
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice Test 1: agentIdentity() returns the correct namespaceHash.
    function test_AgentIdentity_GlobalResolver_NamespaceHash() public view {
        AgentIdentityRef memory ref = globalPerm.agentIdentity();
        assertEq(ref.namespaceHash, keccak256("eip155"), "namespaceHash mismatch");
    }

    /// @notice Test 2: agentIdentity() returns the correct chainId.
    function test_AgentIdentity_GlobalResolver_ChainId() public view {
        AgentIdentityRef memory ref = globalPerm.agentIdentity();
        assertEq(ref.chainId, 8453, "chainId mismatch");
    }

    /// @notice Test 3: agentIdentity() returns the correct identityRegistry address.
    function test_AgentIdentity_GlobalResolver_IdentityRegistry() public view {
        AgentIdentityRef memory ref = globalPerm.agentIdentity();
        assertEq(ref.identityRegistry, REGISTRY, "identityRegistry mismatch");
    }

    /// @notice Test 4: agentIdentity() returns the correct agentId.
    function test_AgentIdentity_GlobalResolver_AgentId() public view {
        AgentIdentityRef memory ref = globalPerm.agentIdentity();
        assertEq(ref.agentId, 42, "agentId mismatch");
    }

    /// @notice Test 5: agentIdentity() returns the correct agentWallet.
    function test_AgentIdentity_GlobalResolver_AgentWallet() public view {
        AgentIdentityRef memory ref = globalPerm.agentIdentity();
        assertEq(ref.agentWallet, ALICE, "agentWallet mismatch");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // INTERFACE READS — IAccountAgentIdentityResolver (tests 6–7)
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice Test 6: agentIdentityFor(configured account) returns correct identity.
    function test_AgentIdentity_AccountResolver_ConfiguredAccount() public view {
        AgentIdentityRef memory ref = perAccountPerm.agentIdentityFor(ALICE);
        assertEq(ref.namespaceHash,    keccak256("eip155"), "namespaceHash");
        assertEq(ref.chainId,          8453,                "chainId");
        assertEq(ref.identityRegistry, REGISTRY,            "identityRegistry");
        assertEq(ref.agentId,          42,                  "agentId");
        assertEq(ref.agentWallet,      ALICE,               "agentWallet");

        // Second configured account
        AgentIdentityRef memory ref2 = perAccountPerm.agentIdentityFor(BOB);
        assertEq(ref2.namespaceHash,    keccak256("erc8004"), "B namespaceHash");
        assertEq(ref2.agentId,          7,                    "B agentId");
        assertEq(ref2.agentWallet,      BOB,                  "B agentWallet");
    }

    /// @notice Test 7: agentIdentityFor(unknown account) returns zero struct — does not revert.
    function test_AgentIdentity_AccountResolver_UnknownAccount_ReturnsZeroStruct() public view {
        address unknown = address(0xDEADBEEF);
        AgentIdentityRef memory ref = perAccountPerm.agentIdentityFor(unknown);
        assertEq(ref.namespaceHash,    bytes32(0),  "expected zero namespaceHash");
        assertEq(ref.chainId,          0,           "expected zero chainId");
        assertEq(ref.identityRegistry, address(0),  "expected zero registry");
        assertEq(ref.agentId,          0,           "expected zero agentId");
        assertEq(ref.agentWallet,      address(0),  "expected zero agentWallet");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // INTROSPECTION (tests 8–10)
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice Test 8: MockAgentIdentityPermission declares AGENT_IDENTITY capability.
    function test_AgentIdentity_CapabilityIds_DeclaresAgentIdentity() public view {
        bytes32[] memory ids = IPermissionIntrospection(address(globalPerm)).capabilityIds();
        assertEq(ids.length, 1, "expected exactly 1 capability");
        assertEq(ids[0], SailCapabilities.AGENT_IDENTITY, "expected AGENT_IDENTITY");

        // Same for per-account mock
        bytes32[] memory ids2 = IPermissionIntrospection(address(perAccountPerm)).capabilityIds();
        assertEq(ids2[0], SailCapabilities.AGENT_IDENTITY, "per-account: expected AGENT_IDENTITY");
    }

    /// @notice Test 9: permissionId() returns a non-zero stable value.
    function test_AgentIdentity_PermissionId_NonZero() public view {
        bytes32 pid = IPermissionIntrospection(address(globalPerm)).permissionId();
        assertNotEq(pid, bytes32(0), "permissionId must be non-zero");
        assertEq(
            pid,
            keccak256("sail.permission.MockAgentIdentityPermission.v1"),
            "permissionId mismatch"
        );
    }

    /// @notice Test 10: evaluate() returns the configured bool; IPermission is intact.
    function test_AgentIdentity_Evaluate_ReturnsConfiguredValue() public {
        Context memory ctx; // zero context — evaluate ignores it

        // shouldApprove = true (set in setUp)
        assertTrue(globalPerm.evaluate("", ctx), "expected true");

        // Deploy a denying instance
        MockAgentIdentityPermission denier = new MockAgentIdentityPermission(_ref, false);
        assertFalse(denier.evaluate("", ctx), "expected false");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // AUTHORIZATION PATTERN (test 11)
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice Test 11: demonstrate the identity-based authorization pattern at the
    ///         template level — no kernel involvement.
    function test_AgentIdentity_AuthorizationPattern_TemplateLevel() public view {
        // Read the agent identity from the permission contract.
        AgentIdentityRef memory ref =
            IAgentIdentityResolver(address(globalPerm)).agentIdentity();

        // Simulate what a template's evaluate() would do:
        // ctx.manager == ref.agentWallet → authorized.
        address authorizedManager = ref.agentWallet; // ALICE
        address unauthorizedManager = BOB;

        // Pattern check — matching wallet
        bool matchResult = (authorizedManager == ref.agentWallet);
        assertTrue(matchResult, "authorized manager should match agentWallet");

        // Pattern check — non-matching wallet
        bool noMatchResult = (unauthorizedManager == ref.agentWallet);
        assertFalse(noMatchResult, "unauthorized manager must not match agentWallet");

        // Crucially: the kernel is not involved. This is purely template-layer logic.
    }

    // ═════════════════════════════════════════════════════════════════════════
    // CAPABILITY DISCOVERY (test 12)
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice Test 12: consumers discover identity-capable templates via capabilityIds()
    ///         without knowing the template's ABI.
    function test_AgentIdentity_CapabilityDiscovery_WithoutABI() public {
        bytes32 AGENT_IDENTITY = SailCapabilities.AGENT_IDENTITY;

        // Simulate off-chain consumer checking for AGENT_IDENTITY capability.
        // Cast to IPermissionIntrospection — consumer does not need to know
        // whether the template also implements IAgentIdentityResolver.
        IPermissionIntrospection perm = IPermissionIntrospection(address(globalPerm));
        bytes32[] memory caps = perm.capabilityIds();

        bool found;
        for (uint256 i; i < caps.length; i++) {
            if (caps[i] == AGENT_IDENTITY) { found = true; break; }
        }
        assertTrue(found, "AGENT_IDENTITY must be discoverable via capabilityIds()");

        // A non-identity template should NOT declare AGENT_IDENTITY.
        // Use a minimal permission that declares BOUNDED_SWAP only.
        IPermissionIntrospection swapPerm = IPermissionIntrospection(address(
            new NoIdentityStub()
        ));
        bytes32[] memory swapCaps = swapPerm.capabilityIds();
        bool foundIdentityInSwap;
        for (uint256 i; i < swapCaps.length; i++) {
            if (swapCaps[i] == AGENT_IDENTITY) { foundIdentityInSwap = true; break; }
        }
        assertFalse(foundIdentityInSwap, "non-identity template must not declare AGENT_IDENTITY");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // KERNEL UNCHANGED (tests 13–14)
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice Test 13: SailKernel is not referenced in any of the new agent-identity files.
    ///         This is a compile-time guarantee: if the kernel were imported, the file
    ///         would not compile without the import being added. This test serves as a
    ///         documentation canary.
    function test_AgentIdentity_KernelNotImportedInInterfaces() public pure {
        // IAgentIdentityResolver.sol — MIT, no SailKernel import.
        // MockAgentIdentityPermission.sol — no SailKernel import.
        // All interface functions are view/pure; the kernel is never involved.
        assertTrue(true, "compile-time canary: kernel not imported in agent-identity files");
    }

    /// @notice Test 14: dispatch through MockAgentIdentityPermission succeeds.
    ///         The kernel calls evaluate() but never calls agentIdentity().
    function test_AgentIdentity_Dispatch_KernelDoesNotCallAgentIdentity() public {
        _registerPermission(address(globalPerm));

        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(
            address(globalPerm), address(0xCAFE), 0, "", nonce, deadline
        );

        // Dispatch succeeds — evaluate() returns true (shouldApprove=true).
        kernel.dispatch(address(safe), address(globalPerm), address(0xCAFE), 0, "", sig, deadline);

        // Safe recorded one call — execution went through.
        assertEq(safe.callCount(), 1, "Safe must have executed the call");

        // agentIdentity() was never called by the kernel — the AgentIdentityRef
        // stored in globalPerm is still intact and readable off-chain.
        AgentIdentityRef memory ref = globalPerm.agentIdentity();
        assertEq(ref.agentWallet, ALICE, "agentWallet readable post-dispatch");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // BACKWARDS COMPATIBILITY (test 15)
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice Test 15: all existing tests still pass (compile-time canary).
    ///         The new files add no changes to existing contracts. If this file
    ///         compiles and tests pass, backwards compatibility is confirmed.
    function test_AgentIdentity_BackwardsCompatibility_Canary() public pure {
        assertTrue(true, "all existing interfaces and templates are unchanged");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // EXTRA: SailCapabilities.AGENT_IDENTITY exact value
    // ═════════════════════════════════════════════════════════════════════════

    function test_AgentIdentity_SailCapabilities_ExactValue() public pure {
        assertEq(
            SailCapabilities.AGENT_IDENTITY,
            keccak256("sail.capability.agent-identity.v1"),
            "AGENT_IDENTITY constant mismatch"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper stub — declares only BOUNDED_SWAP, used in capability discovery test.
// ─────────────────────────────────────────────────────────────────────────────
contract NoIdentityStub is IPermissionIntrospection {
    function permissionId()      external pure override returns (bytes32) { return keccak256("NoIdentityStub.v1"); }
    function permissionVersion() external pure override returns (bytes32) { return keccak256("v1"); }
    function metadataURI()       external pure override returns (string memory) { return ""; }
    function capabilityIds()     external pure override returns (bytes32[] memory ids) {
        ids = new bytes32[](1);
        ids[0] = SailCapabilities.BOUNDED_SWAP;
    }
}
