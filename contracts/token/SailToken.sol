// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {ERC20}             from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Capped}       from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Capped.sol";
import {ERC20Permit}       from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {ERC20Votes}        from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";
import {Nonces}            from "@openzeppelin/contracts/utils/Nonces.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

/// @title  SailToken — the $SAIL governance/utility token
/// @notice Full multi-bucket $SAIL token: a hard-capped, initially non-transferable ERC-20 that
///         holds the entire investor / team / treasury / foundation / liquidity / community
///         allocation and gates a single, IRREVERSIBLE public-transferability switch.
///
/// @dev    SECURITY MODEL (read before changing anything):
///
///         1. NON-UPGRADEABLE, NO OWNER. There is no proxy and no standing owner role. Every
///            privileged action (`mintGenesis`, `openSeason`, `enablePublicTransfers`) is gated by
///            a 48-hour `TimelockController` (the same pattern, and the same constructor invariants,
///            that `SailGovernance` enforces). Immutability *is* the security model.
///
///         2. PLAIN ERC-20 — NO TRANSFER CALLBACKS. This contract makes ZERO external calls on any
///            mint or transfer path (no ERC777/ERC1363/flash-mint hooks). There is therefore no
///            reentrancy surface in the token itself.
///
///         3. ONE MINT CHOKEPOINT. Every mint — constructor allocations, the one-shot genesis, and
///            every weekly emission — funnels through `_mintBucket`, which enforces both the
///            per-bucket cap and (redundantly, via `ERC20Capped`) the 1B global cap. No other mint
///            path exists after construction except `pullWeeklyEmission` (permissionless, rate-
///            limited, season-bounded) and the one-shot latched `mintGenesis`.
///
///         4. ONE-WAY TRANSFER SWITCH. `_transfersEnabled` is written exactly once, to `true`, by
///            `enablePublicTransfers`. There is no code path that writes it `false`. Re-locking is
///            impossible by construction, not by policy.
///
/// @custom:security-contact security@sail.money
contract SailToken is ERC20, ERC20Capped, ERC20Permit, ERC20Votes {
    // -------------------------------------------------------------------------
    // Buckets & caps — immutable; sum == HARD_CAP (asserted at construction)
    // -------------------------------------------------------------------------

    /// @notice The allocation buckets. The COMMUNITY bucket is the only one minted post-deploy
    ///         (genesis + weekly emission); the other five are minted in full at construction.
    enum Bucket {
        COMMUNITY,   // 40% — funds genesis + all seasonal emission
        TEAM,        // 20%
        INVESTORS,   // 20%
        TREASURY,    // 12% — DAO/Treasury (NOTE: this is NOT the rewards source; frozen pre-flip)
        FOUNDATION,  //  6%
        LIQUIDITY    //  2%
    }

    /// @notice Immutable hard cap: 1,000,000,000 $SAIL. No mechanism can raise it.
    uint256 public constant HARD_CAP    = 1_000_000_000e18;

    uint256 public constant CAP_COMMUNITY  = 400_000_000e18; // 40%
    uint256 public constant CAP_TEAM       = 200_000_000e18; // 20%
    uint256 public constant CAP_INVESTORS  = 200_000_000e18; // 20%
    uint256 public constant CAP_TREASURY   = 120_000_000e18; // 12%
    uint256 public constant CAP_FOUNDATION =  60_000_000e18; //  6%
    uint256 public constant CAP_LIQUIDITY  =  20_000_000e18; //  2%

    /// @notice 0.2% genesis distribution ceiling (drawn from the community bucket). Immutable.
    uint256 public constant GENESIS_MAX = 2_000_000e18;

    /// @notice Upper bound on a season's week count (D10). Bounds season duration / config blast radius.
    uint32  public constant MAX_WEEKS   = 104;

    /// @notice Required timelock minimum delay — must match SailGovernance.REQUIRED_TIMELOCK_DELAY.
    uint256 public constant REQUIRED_TIMELOCK_DELAY = 48 hours;

    /// @notice Cumulative amount minted per bucket. Only ever increases, only via `_mintBucket`.
    mapping(Bucket => uint256) public mintedOf;

    // -------------------------------------------------------------------------
    // Immutable wiring
    // -------------------------------------------------------------------------

    /// @notice The ONLY non-mint source allowed to move tokens before the transfer switch is
    ///         flipped — the rewards SMA (a.k.a. the rewards treasury). Immutable so a compromised
    ///         admin can never repoint the distribution source to drain or bypass the freeze.
    address public immutable REWARDS_SOURCE;

    /// @notice 48-hour timelock gating every privileged action. Validated at construction.
    TimelockController public immutable timelock;

    // -------------------------------------------------------------------------
    // Mutable state (deliberately minimal)
    // -------------------------------------------------------------------------

    /// @notice The single active season (Pattern C). Only one season exists at a time; a new season
    ///         cannot open until the prior is fully pulled. No automatic continuation.
    struct Season {
        uint64  start;        // unix ts; tranche 0 unlocks at `start`
        uint32  numWeeks;     // number of weekly tranches
        uint32  weeksPulled;  // cursor — strictly < numWeeks while pullable
        uint128 weeklyRate;   // tokens minted per tranche
        uint128 budget;       // == weeklyRate * numWeeks (exact; asserted at open)
        bool    active;       // false once fully pulled or never opened
    }
    Season public season;

    /// @notice Monotonic season id (incremented on each open). The active season's id == seasonCount.
    uint256 public seasonCount;

    /// @notice One-way latch for the 0.2% genesis distribution.
    bool public genesisMinted;

    /// @dev Internal one-way transfer switch. Written exactly once, to `true`. Never set false.
    bool private _transfersEnabled;

    /// @notice Block timestamp at which public transfers were enabled (0 until the flip).
    ///         Exposed so vesting vaults can anchor their cliffs to the flip / TGE (decision D2).
    uint256 public transfersEnabledAt;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted for every allocation mint (constructor buckets).
    event AllocationMinted(Bucket indexed bucket, address indexed to, uint256 amount);
    /// @notice Emitted once when the genesis distribution is minted to the rewards source.
    event GenesisMinted(address indexed to, uint256 amount);
    /// @notice Emitted when governance opens a new season.
    event SeasonOpened(uint256 indexed seasonId, uint64 start, uint32 numWeeks, uint128 weeklyRate, uint256 budget);
    /// @notice Emitted on each successful weekly emission pull.
    event EmissionPulled(uint256 indexed seasonId, uint32 weekIndex, address indexed to, uint256 amount);
    /// @notice Emitted exactly once, when public transfers are irreversibly enabled.
    event TransfersEnabled(uint256 timestamp);

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    error ZeroAddress();
    error CapSumMismatch();
    error NotTimelock();
    error TransfersLocked();
    error TransfersAlreadyEnabled();
    error BucketCapExceeded(Bucket bucket, uint256 attempted, uint256 cap);
    error GenesisAlreadyMinted();
    error ZeroAmount();
    error ExceedsGenesisMax(uint256 requested, uint256 cap);
    error SeasonActive();
    error PreviousSeasonUnfinished();
    error InvalidWeeks(uint32 numWeeks);
    error ZeroRate();
    error StartInPast(uint64 start, uint256 nowTs);
    error ExceedsCommunityBucket(uint256 attempted, uint256 cap);
    error NoActiveSeason();
    error SeasonExhausted();
    error TrancheNotYetUnlocked(uint256 unlockTime, uint256 nowTs);

    // Timelock validation errors — mirror SailGovernance.
    error TimelockDelayMismatch();
    error GovernanceNotProposer();
    error GovernanceNotExecutor();
    error TimelockNotSelfAdministered();

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------

    /// @dev Reverts unless the caller is the timelock. All privileged actions use this.
    modifier onlyTimelock() {
        if (msg.sender != address(timelock)) revert NotTimelock();
        _;
    }

    // -------------------------------------------------------------------------
    // Constructor — mints the five non-community buckets in full, to custody addresses
    // -------------------------------------------------------------------------

    /// @notice Deploy $SAIL, mint the 60% non-community allocation to custody addresses, and wire
    ///         the rewards source + timelock. The community bucket (40%) starts unminted and is
    ///         filled incrementally via `mintGenesis` + `pullWeeklyEmission`.
    ///
    /// @dev    Allocation is ALL-AT-DEPLOY (no standing allocation mint function): after this
    ///         constructor the only mint paths in existence are the latched `mintGenesis` and the
    ///         season-bounded `pullWeeklyEmission`. Custody addresses are deploy-time inputs (they
    ///         will be the vesting-vault / Safe contracts — vesting is enforced off-token).
    ///
    ///         The timelock is validated against the SAME invariants SailGovernance enforces:
    ///         non-zero, minimum delay EXACTLY 48 hours, `initialGovernance` holds PROPOSER_ROLE
    ///         and EXECUTOR_ROLE, and the timelock self-administers its roles (admin == address(0)).
    ///
    /// @param  investorsCustody   Recipient of the full INVESTORS bucket (20%).
    /// @param  teamCustody        Recipient of the full TEAM bucket (20%).
    /// @param  treasuryCustody    Recipient of the full TREASURY/DAO bucket (12%).
    /// @param  foundationCustody  Recipient of the full FOUNDATION bucket (6%).
    /// @param  liquidityCustody   Recipient of the full LIQUIDITY bucket (2%).
    /// @param  rewardsSource      The rewards SMA — the only non-mint transfer source allowed pre-flip.
    /// @param  initialGovernance  Address that must hold PROPOSER_ROLE and EXECUTOR_ROLE on `_timelock`.
    /// @param  _timelock          Pre-deployed, self-administered, 48-hour TimelockController.
    constructor(
        address investorsCustody,
        address teamCustody,
        address treasuryCustody,
        address foundationCustody,
        address liquidityCustody,
        address rewardsSource,
        address initialGovernance,
        TimelockController _timelock
    )
        ERC20("Sail", "SAIL")
        ERC20Capped(HARD_CAP)
        ERC20Permit("Sail")
    {
        if (
            investorsCustody  == address(0) ||
            teamCustody       == address(0) ||
            treasuryCustody   == address(0) ||
            foundationCustody == address(0) ||
            liquidityCustody  == address(0) ||
            rewardsSource     == address(0) ||
            initialGovernance == address(0) ||
            address(_timelock) == address(0)
        ) revert ZeroAddress();

        // Defense-in-depth: the per-bucket caps must sum to exactly the global hard cap, so that
        // respecting per-bucket limits structurally implies respecting the global cap.
        if (
            CAP_COMMUNITY + CAP_TEAM + CAP_INVESTORS + CAP_TREASURY + CAP_FOUNDATION + CAP_LIQUIDITY
            != HARD_CAP
        ) revert CapSumMismatch();

        // Validate the injected timelock exactly as SailGovernance does (D6).
        if (_timelock.getMinDelay() != REQUIRED_TIMELOCK_DELAY) revert TimelockDelayMismatch();
        if (!_timelock.hasRole(_timelock.PROPOSER_ROLE(), initialGovernance)) revert GovernanceNotProposer();
        if (!_timelock.hasRole(_timelock.EXECUTOR_ROLE(), initialGovernance)) revert GovernanceNotExecutor();
        bytes32 proposerAdminRole = _timelock.getRoleAdmin(_timelock.PROPOSER_ROLE());
        if (!_timelock.hasRole(proposerAdminRole, address(_timelock))) revert TimelockNotSelfAdministered();
        if (_timelock.hasRole(proposerAdminRole, initialGovernance))   revert TimelockNotSelfAdministered();

        REWARDS_SOURCE = rewardsSource;
        timelock       = _timelock;

        // Mint the five non-community buckets in full, once. (COMMUNITY stays at 0.)
        _mintBucket(Bucket.TEAM,       teamCustody,       CAP_TEAM);
        _mintBucket(Bucket.INVESTORS,  investorsCustody,  CAP_INVESTORS);
        _mintBucket(Bucket.TREASURY,   treasuryCustody,   CAP_TREASURY);
        _mintBucket(Bucket.FOUNDATION, foundationCustody, CAP_FOUNDATION);
        _mintBucket(Bucket.LIQUIDITY,  liquidityCustody,  CAP_LIQUIDITY);
    }

    // -------------------------------------------------------------------------
    // Mint chokepoint — the ONLY place tokens are created
    // -------------------------------------------------------------------------

    /// @dev Single mint chokepoint. Enforces the per-bucket cap; `_mint` -> `_update(0, to, amount)`
    ///      additionally enforces the global cap via `ERC20Capped`. No external calls.
    function _mintBucket(Bucket bucket, address to, uint256 amount) private {
        uint256 attempted = mintedOf[bucket] + amount; // checked add (Solidity 0.8)
        uint256 cap       = bucketCap(bucket);
        if (attempted > cap) revert BucketCapExceeded(bucket, attempted, cap);
        mintedOf[bucket] = attempted;
        _mint(to, amount);
    }

    /// @notice The immutable cap for a given bucket.
    function bucketCap(Bucket bucket) public pure returns (uint256) {
        if (bucket == Bucket.COMMUNITY)  return CAP_COMMUNITY;
        if (bucket == Bucket.TEAM)       return CAP_TEAM;
        if (bucket == Bucket.INVESTORS)  return CAP_INVESTORS;
        if (bucket == Bucket.TREASURY)   return CAP_TREASURY;
        if (bucket == Bucket.FOUNDATION) return CAP_FOUNDATION;
        return CAP_LIQUIDITY; // Bucket.LIQUIDITY
    }

    // -------------------------------------------------------------------------
    // Genesis distribution — one-shot, latched, capped, timelocked
    // -------------------------------------------------------------------------

    /// @notice Mint the one-time genesis distribution (<= 0.2% of cap) to the rewards source.
    /// @dev    Latches `genesisMinted` BEFORE minting. Draws from the COMMUNITY bucket counter, so
    ///         genesis + all future seasons can never collectively exceed the 40% community bucket.
    /// @param  amount Tokens to mint, in wei. Must be > 0 and <= GENESIS_MAX.
    function mintGenesis(uint256 amount) external onlyTimelock {
        if (genesisMinted) revert GenesisAlreadyMinted();
        if (amount == 0) revert ZeroAmount();
        if (amount > GENESIS_MAX) revert ExceedsGenesisMax(amount, GENESIS_MAX);
        genesisMinted = true; // effect before mint
        _mintBucket(Bucket.COMMUNITY, REWARDS_SOURCE, amount);
        emit GenesisMinted(REWARDS_SOURCE, amount);
    }

    // -------------------------------------------------------------------------
    // Seasons — governance opens, behind the 48h timelock
    // -------------------------------------------------------------------------

    /// @notice Open a new emission season. Reverts unless the previous season is fully pulled.
    /// @dev    Guards against: overlap (`active`), unfinished prior season, bad week count, zero
    ///         rate, retroactive start (which would unlock a whole backlog at once), and a budget
    ///         that would exceed the remaining community bucket. `budget == weeklyRate * numWeeks`
    ///         exactly. Season 1 = openSeason(start, 12, 5_000_000e18) => 60M budget.
    /// @param  start      Unix timestamp at which tranche 0 unlocks. Must be >= now.
    /// @param  numWeeks   Number of weekly tranches (1..MAX_WEEKS).
    /// @param  weeklyRate Tokens minted per tranche (> 0).
    function openSeason(uint64 start, uint32 numWeeks, uint128 weeklyRate) external onlyTimelock {
        if (season.active) revert SeasonActive();
        if (season.weeksPulled != season.numWeeks) revert PreviousSeasonUnfinished();
        if (numWeeks == 0 || numWeeks > MAX_WEEKS) revert InvalidWeeks(numWeeks);
        if (weeklyRate == 0) revert ZeroRate();
        if (start < block.timestamp) revert StartInPast(start, block.timestamp);

        uint256 budget = uint256(weeklyRate) * uint256(numWeeks); // checked mul
        uint256 remaining = mintedOf[Bucket.COMMUNITY];
        if (remaining + budget > CAP_COMMUNITY) revert ExceedsCommunityBucket(remaining + budget, CAP_COMMUNITY);
        // `budget <= CAP_COMMUNITY` here (it passed the check above), so the uint128 cast cannot truncate.

        season = Season({
            start:       start,
            numWeeks:    numWeeks,
            weeksPulled: 0,
            weeklyRate:  weeklyRate,
            budget:      uint128(budget),
            active:      true
        });
        unchecked { seasonCount += 1; } // cannot realistically overflow uint256
        emit SeasonOpened(seasonCount, start, numWeeks, weeklyRate, budget);
    }

    // -------------------------------------------------------------------------
    // Weekly emission — permissionless, rate-limited, season- and cap-bounded
    // -------------------------------------------------------------------------

    /// @notice Mint the active season's next weekly tranche to the rewards source. PERMISSIONLESS.
    /// @dev    The caller controls NO parameters: recipient (rewards source) and amount (the season
    ///         weekly rate) are fixed. Permissionless-ness only affects liveness (no keyholder can
    ///         censor emission), never the destination or amount.
    ///
    ///         Time-gate: tranche `n` unlocks at `season.start + n * 1 week` (anchored to the season
    ///         start, NOT to the last pull — so a late pull does not drift future unlocks). Catch-up
    ///         is allowed (decision D5): if several unlock times have passed, several pulls become
    ///         available, but the total is still bounded by `budget` and the community cap.
    ///
    ///         block.timestamp manipulation is bounded to a few seconds by proposers — negligible
    ///         against a 604,800-second (1 week) cadence; it cannot manufacture an extra tranche.
    /// @return amount The tranche amount minted.
    function pullWeeklyEmission() external returns (uint256 amount) {
        Season storage s = season;
        if (!s.active) revert NoActiveSeason();
        // Defensive double-guard: `active` should already be false here, but never pull past the end.
        if (s.weeksPulled >= s.numWeeks) revert SeasonExhausted();

        uint256 unlockTime = uint256(s.start) + uint256(s.weeksPulled) * 1 weeks;
        if (block.timestamp < unlockTime) revert TrancheNotYetUnlocked(unlockTime, block.timestamp);

        amount = s.weeklyRate;
        uint32 newWeeksPulled = s.weeksPulled + 1;
        s.weeksPulled = newWeeksPulled;
        if (newWeeksPulled == s.numWeeks) s.active = false; // auto-close after the last week

        // Effects done; mint last. `_mintBucket` enforces the community + global caps as a backstop
        // even if a season were somehow misconfigured.
        _mintBucket(Bucket.COMMUNITY, REWARDS_SOURCE, amount);
        emit EmissionPulled(seasonCount, newWeeksPulled, REWARDS_SOURCE, amount);
    }

    // -------------------------------------------------------------------------
    // One-way transferability switch — irreversible by construction
    // -------------------------------------------------------------------------

    /// @notice Irreversibly enable public transfers. Behind the 48-hour timelock.
    /// @dev    `_transfersEnabled` is written `true` here and NOWHERE ELSE in the contract; there is
    ///         no function that sets it `false`. Re-locking is impossible by construction.
    function enablePublicTransfers() external onlyTimelock {
        if (_transfersEnabled) revert TransfersAlreadyEnabled();
        _transfersEnabled  = true;
        transfersEnabledAt = block.timestamp;
        emit TransfersEnabled(block.timestamp);
    }

    /// @notice True once public transfers have been (irreversibly) enabled.
    function transfersEnabled() external view returns (bool) {
        return _transfersEnabled;
    }

    // -------------------------------------------------------------------------
    // Transfer gate + OZ overrides
    // -------------------------------------------------------------------------

    /// @dev The non-transferability predicate + the OZ `_update` diamond (ERC20 / ERC20Capped /
    ///      ERC20Votes). Before the flip, only two source cases are allowed:
    ///        - mint        : from == address(0)
    ///        - distribution: from == REWARDS_SOURCE (rewards SMA -> anyone)
    ///      Everything else (user->user, investor/team/treasury/foundation custody -> anyone,
    ///      user->rewards source, any burn) reverts. Fail-closed: it is a source ALLOWLIST.
    ///      `super._update` applies the global cap check (ERC20Capped) and the voting checkpoint
    ///      (ERC20Votes).
    function _update(address from, address to, uint256 value)
        internal
        override(ERC20, ERC20Capped, ERC20Votes)
    {
        if (!_transfersEnabled) {
            bool isMint         = from == address(0);
            bool isDistribution = from == REWARDS_SOURCE;
            if (!isMint && !isDistribution) revert TransfersLocked();
        }
        super._update(from, to, value);
    }

    /// @dev Resolve the `nonces` diamond between ERC20Permit and Nonces.
    function nonces(address owner)
        public
        view
        override(ERC20Permit, Nonces)
        returns (uint256)
    {
        return super.nonces(owner);
    }
}
