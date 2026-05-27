// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title  SafeConstants
/// @notice Canonical Safe v1.4.1 contract addresses and the SafeProxy runtime codehash
///         required to populate the SailGovernance onboarding allowlists.
///
/// @dev    These are consumed by the post-deploy governance step that calls, via the
///         48-hour timelock:
///           • SailGovernance.setTrustedSafeFactory(SAFE_PROXY_FACTORY_1_4_1, true)
///           • SailGovernance.setTrustedSafeSingleton(SAFE_SINGLETON_1_4_1, true)
///           • SailGovernance.setTrustedModuleSetup(<Sail SafeModuleEnabler>, true)
///           • SailGovernance.setTrustedSafeProxyCodehash(SAFE_PROXY_CODEHASH_1_4_1, true)
///
///         NOTE: the kernel validates the `to` target embedded in `safeInitializer` against
///         `trustedModuleSetup`. The intended target is the Sail-deployed `SafeModuleEnabler`
///         (see contracts/safe/SafeModuleEnabler.sol), so allowlist that deployed address —
///         NOT the canonical Safe `SafeModuleSetup` below (kept here for reference only).
///
///         The allowlist setters are `onlyTimelock`, so they CANNOT be populated inline in
///         the deployment broadcast — they must be scheduled and executed through the
///         48-hour timelock after `DeployCore` runs. `DeployCore` logs these values as a
///         reminder; it does not (and cannot) call the setters directly.
///
///         Canonical Safe v1.4.1 deterministic deployments (identical across all EVM chains
///         that used the Safe singleton-factory deployment):
///           SafeProxyFactory  https://github.com/safe-global/safe-smart-account (v1.4.1)
///           SafeModuleSetup   enables modules via Safe.setup's delegatecall hook
library SafeConstants {
    /// @notice Safe v1.4.1 SafeProxyFactory (deterministic across chains).
    address internal constant SAFE_PROXY_FACTORY_1_4_1 = 0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67;

    /// @notice Safe v1.4.1 L2 singleton (SafeL2). Use the non-L2 `Safe` singleton
    ///         (0x41675C099F32341bf84BFc5382aF534df5C7461a) instead on chains where the
    ///         non-L2 variant is the convention; allowlist whichever the deployment uses.
    address internal constant SAFE_SINGLETON_L2_1_4_1 = 0x29fcB43b46531BcA003ddC8FCB67FFE91900C762;

    /// @notice Safe v1.4.1 non-L2 singleton (`Safe`).
    address internal constant SAFE_SINGLETON_1_4_1 = 0x41675C099F32341bf84BFc5382aF534df5C7461a;

    /// @notice Safe v1.4.1 SafeModuleSetup helper. Implements `enableModules(address[])`,
    ///         delegatecalled during Safe.setup. This is the ONLY permitted `to` target of
    ///         the kernel-constructed initializer's setup delegatecall.
    address internal constant SAFE_MODULE_SETUP_1_4_1 = 0x2dd68b007B46fBe91B9A7c3EDa5A7a1063cB5b47;

    /// @notice keccak256 of the deployed SafeProxy v1.4.1 runtime bytecode.
    /// @dev    MUST be captured from chain before going live: read `extcodehash` of any
    ///         SafeProxy deployed by SAFE_PROXY_FACTORY_1_4_1 on the target chain and set
    ///         this constant to that value. The SafeProxy runtime code is identical across
    ///         all proxies from the same factory, so a single capture is authoritative per
    ///         factory version. Left as bytes32(0) here so a careless deploy fails loudly:
    ///         SailGovernance.setTrustedSafeProxyCodehash reverts ZeroCodehash on bytes32(0).
    bytes32 internal constant SAFE_PROXY_CODEHASH_1_4_1 = bytes32(0);
}
