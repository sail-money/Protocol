// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import {Context}                from "../contracts/interfaces/IPermission.sol";
import {SailCapabilities}       from "../contracts/interfaces/SailCapabilities.sol";
import {SwapPermissionNoOracle} from "../contracts/templates/SwapPermissionNoOracle.sol";

/// @dev Minimal kernel view: every account registered; this test contract is the permissionSigner.
contract NoOracleMockKernel {
    address public immutable signer;
    constructor(address _signer) { signer = _signer; }
    function registered(address) external pure returns (bool) { return true; }
    function configs(address) external view returns (address) { return signer; }
}

/// @notice Tests for SwapPermissionNoOracle: it enforces token/router allowlists, a per-tx cap,
///         the recipient pin, and a NON-ZERO amountOutMin floor — but NO price band. The floor is
///         deliberately weak; these tests document that an arbitrarily small (but non-zero)
///         minimum-out is accepted.
contract SwapPermissionNoOracleTest is Test {
    bytes4 internal constant EXACT_INPUT_SINGLE_V1 = 0x414bf389; // V3 SwapRouter (with deadline)
    bytes4 internal constant EXACT_INPUT_SINGLE_V2 = 0x04e45aaf; // V3 SwapRouter02 (no deadline)
    bytes4 internal constant SWAP_EXACT_TOKENS     = 0x38ed1739; // V2 swapExactTokensForTokens

    address internal constant AUTHOR  = address(0xA11CE);
    address internal constant ACCOUNT = address(0xACC0);
    address internal constant ROUTER  = address(0x9000);
    address internal constant TOKIN   = address(0x0100);
    address internal constant TOKOUT  = address(0x0200);
    address internal constant OTHER   = address(0xBEEF);

    NoOracleMockKernel       internal kernel;
    SwapPermissionNoOracle   internal swap;

    function setUp() public {
        kernel = new NoOracleMockKernel(address(this)); // this contract is the permissionSigner
        swap   = new SwapPermissionNoOracle(address(kernel), AUTHOR);
        _configure(1000 ether);
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    function _one(address a) internal pure returns (address[] memory arr) { arr = new address[](1); arr[0] = a; }

    function _configure(uint256 cap) internal {
        swap.configureDirect(ACCOUNT, abi.encode(_one(ROUTER), _one(TOKIN), _one(TOKOUT), cap));
    }

    function _ctx(address target, bytes4 selector) internal view returns (Context memory c) {
        c = Context({
            account:        ACCOUNT,
            manager:        address(0),
            submitter:      address(0),
            target:         target,
            selector:       selector,
            value:          0,
            blockTimestamp: block.timestamp,
            blockNumber:    block.number
        });
    }

    // V3 SwapRouter exactInputSingle calldata (260 bytes)
    function _v3(address tokenIn, address tokenOut, address recipient, uint256 amtIn, uint256 amtOutMin)
        internal view returns (bytes memory)
    {
        return abi.encodeWithSelector(
            EXACT_INPUT_SINGLE_V1,
            tokenIn, tokenOut, uint24(3000), recipient,
            uint256(block.timestamp + 1), amtIn, amtOutMin, uint160(0)
        );
    }

    // V3 SwapRouter02 exactInputSingle calldata (228 bytes, no deadline)
    function _v3_02(address tokenIn, address tokenOut, address recipient, uint256 amtIn, uint256 amtOutMin)
        internal pure returns (bytes memory)
    {
        return abi.encodeWithSelector(
            EXACT_INPUT_SINGLE_V2,
            tokenIn, tokenOut, uint24(3000), recipient, amtIn, amtOutMin, uint160(0)
        );
    }

    // V2 swapExactTokensForTokens calldata
    function _v2(address[] memory path, address to, uint256 amtIn, uint256 amtOutMin)
        internal view returns (bytes memory)
    {
        return abi.encodeWithSelector(SWAP_EXACT_TOKENS, amtIn, amtOutMin, path, to, block.timestamp + 1);
    }

    function _path(address a, address b) internal pure returns (address[] memory p) {
        p = new address[](2); p[0] = a; p[1] = b;
    }

    // ── introspection / author ─────────────────────────────────────────────────

    function test_Author_IsRecorded() public view {
        assertEq(swap.author(), AUTHOR);
    }

    function test_Introspection_Ids() public view {
        assertEq(swap.discriminator(), keccak256("SwapPermissionNoOracle"));
        assertEq(swap.permissionId(),  keccak256("sail.permission.SwapPermissionNoOracle.v1"));
        bytes32[] memory ids = swap.capabilityIds();
        assertEq(ids.length, 1);
        assertEq(ids[0], SailCapabilities.SWAP_NO_ORACLE);
    }

    function test_Config_NoOracleFields() public view {
        (address[] memory routers, address[] memory tIn, address[] memory tOut, uint256 cap) = swap.getConfig(ACCOUNT);
        assertEq(routers.length, 1); assertEq(routers[0], ROUTER);
        assertEq(tIn[0], TOKIN); assertEq(tOut[0], TOKOUT); assertEq(cap, 1000 ether);
    }

    // ── the load-bearing property: non-zero floor, NO band ───────────────────────

    function test_AmountOutMinZero_IsDenied_V3() public view {
        assertFalse(swap.evaluate(_v3(TOKIN, TOKOUT, ACCOUNT, 1 ether, 0), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_AmountOutMinNonZero_IsAllowed_V3() public view {
        assertTrue(swap.evaluate(_v3(TOKIN, TOKOUT, ACCOUNT, 1 ether, 1), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    /// @notice Documents the honest limitation: a tiny (but non-zero) minimum-out passes. There is
    ///         NO slippage band — price protection is entirely the manager's amountOutMin.
    function test_TinyAmountOutMin_StillPasses_NoBandClaimed() public view {
        assertTrue(swap.evaluate(_v3(TOKIN, TOKOUT, ACCOUNT, 1000 ether, 1), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    // ── both decode paths ────────────────────────────────────────────────────────

    function test_V3_02_Path_Allows() public view {
        assertTrue(swap.evaluate(_v3_02(TOKIN, TOKOUT, ACCOUNT, 1 ether, 1), _ctx(ROUTER, EXACT_INPUT_SINGLE_V2)));
    }

    function test_V3_02_Path_ZeroMinOut_Denied() public view {
        assertFalse(swap.evaluate(_v3_02(TOKIN, TOKOUT, ACCOUNT, 1 ether, 0), _ctx(ROUTER, EXACT_INPUT_SINGLE_V2)));
    }

    function test_V2_Path_Allows() public view {
        assertTrue(swap.evaluate(_v2(_path(TOKIN, TOKOUT), ACCOUNT, 1 ether, 1), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    function test_V2_Path_ZeroMinOut_Denied() public view {
        assertFalse(swap.evaluate(_v2(_path(TOKIN, TOKOUT), ACCOUNT, 1 ether, 0), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    // ── structural denials (shared with the oracle template) ─────────────────────

    function test_DisallowedRouter_Denied() public view {
        assertFalse(swap.evaluate(_v3(TOKIN, TOKOUT, ACCOUNT, 1 ether, 1), _ctx(OTHER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_DisallowedTokenIn_Denied() public view {
        assertFalse(swap.evaluate(_v3(OTHER, TOKOUT, ACCOUNT, 1 ether, 1), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_DisallowedTokenOut_Denied() public view {
        assertFalse(swap.evaluate(_v3(TOKIN, OTHER, ACCOUNT, 1 ether, 1), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_RecipientNotAccount_Denied() public view {
        assertFalse(swap.evaluate(_v3(TOKIN, TOKOUT, OTHER, 1 ether, 1), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_V2_RecipientNotAccount_Denied() public view {
        assertFalse(swap.evaluate(_v2(_path(TOKIN, TOKOUT), OTHER, 1 ether, 1), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    function test_OverCap_Denied() public {
        _configure(1 ether);
        assertFalse(swap.evaluate(_v3(TOKIN, TOKOUT, ACCOUNT, 5 ether, 1), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_AtCap_Allowed() public {
        _configure(5 ether);
        assertTrue(swap.evaluate(_v3(TOKIN, TOKOUT, ACCOUNT, 5 ether, 1), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_UnknownSelector_Denied() public view {
        assertFalse(swap.evaluate(_v3(TOKIN, TOKOUT, ACCOUNT, 1 ether, 1), _ctx(ROUTER, 0xdeadbeef)));
    }

    function test_ShortCalldata_Denied() public view {
        bytes memory short = abi.encodeWithSelector(EXACT_INPUT_SINGLE_V1, TOKIN);
        assertFalse(swap.evaluate(short, _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_V2_ShortPath_Denied() public view {
        address[] memory p = new address[](1); p[0] = TOKIN; // path < 2
        assertFalse(swap.evaluate(_v2(p, ACCOUNT, 1 ether, 1), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    // ── per-path denials: SwapRouter02 (V3-02) ──────────────────────────────────

    function test_V3_02_DisallowedTokenIn_Denied() public view {
        assertFalse(swap.evaluate(_v3_02(OTHER, TOKOUT, ACCOUNT, 1 ether, 1), _ctx(ROUTER, EXACT_INPUT_SINGLE_V2)));
    }

    function test_V3_02_DisallowedTokenOut_Denied() public view {
        assertFalse(swap.evaluate(_v3_02(TOKIN, OTHER, ACCOUNT, 1 ether, 1), _ctx(ROUTER, EXACT_INPUT_SINGLE_V2)));
    }

    function test_V3_02_RecipientNotAccount_Denied() public view {
        assertFalse(swap.evaluate(_v3_02(TOKIN, TOKOUT, OTHER, 1 ether, 1), _ctx(ROUTER, EXACT_INPUT_SINGLE_V2)));
    }

    function test_V3_02_OverCap_Denied() public {
        _configure(1 ether);
        assertFalse(swap.evaluate(_v3_02(TOKIN, TOKOUT, ACCOUNT, 5 ether, 1), _ctx(ROUTER, EXACT_INPUT_SINGLE_V2)));
    }

    function test_V3_02_ShortCalldata_Denied() public view {
        bytes memory short = abi.encodeWithSelector(EXACT_INPUT_SINGLE_V2, TOKIN);
        assertFalse(swap.evaluate(short, _ctx(ROUTER, EXACT_INPUT_SINGLE_V2)));
    }

    // ── per-path denials: V2 swapExactTokensForTokens ───────────────────────────

    function test_V2_DisallowedTokenIn_Denied() public view {
        assertFalse(swap.evaluate(_v2(_path(OTHER, TOKOUT), ACCOUNT, 1 ether, 1), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    function test_V2_DisallowedTokenOut_Denied() public view {
        assertFalse(swap.evaluate(_v2(_path(TOKIN, OTHER), ACCOUNT, 1 ether, 1), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    function test_V2_OverCap_Denied() public {
        _configure(1 ether);
        assertFalse(swap.evaluate(_v2(_path(TOKIN, TOKOUT), ACCOUNT, 5 ether, 1), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    function test_V3_ShortCalldata_Denied() public view {
        bytes memory short = abi.encodeWithSelector(EXACT_INPUT_SINGLE_V1, TOKIN);
        assertFalse(swap.evaluate(short, _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }
}
