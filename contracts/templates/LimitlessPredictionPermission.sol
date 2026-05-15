// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IPermission, Context} from "../interfaces/IPermission.sol";

/// @notice Gates Limitless CTF Exchange `fillOrder` calls so the manager can
///         only fill prediction-market orders where the Safe is the maker,
///         within approved market token IDs, within a position-size cap, and
///         in the allowed direction (long / short).
///
///         Limitless CTF Exchange is a Polymarket CTF Exchange fork on Base.
///         Safe wallets sign orders using SignatureType.LIMITLESS_SAFE.
///
///         Supported selector:
///           fillOrder((address,address,address,uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint8,uint8,bytes),uint256)
contract LimitlessPredictionPermission is IPermission {
    // fillOrder((address,address,address,uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint8,uint8,bytes),uint256)
    bytes4 private constant FILL_ORDER = bytes4(
        keccak256(
            "fillOrder((address,address,address,uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint8,uint8,bytes),uint256)"
        )
    );

    // Minimum calldata:
    //   4   selector
    //  32   offset to Order tuple (0x40, dynamic due to bytes signature)
    //  32   fillAmount
    //  13×32 = 416  Order fixed fields (maker,signer,taker,tokenId,makerAmount,
    //                takerAmount,salt,expiration,nonce,feeRateBps,side,
    //                signatureType,signature_offset)
    //  32   signature length word (0 for empty)
    // ────────────────────────────────────────────────────────────────────────
    // Total = 4 + 32 + 32 + 416 + 32 = 516
    uint256 private constant MIN_CALLDATA_LEN = 516;

    // Side enum values (matches Polymarket/Limitless CTF Exchange)
    uint8 private constant SIDE_BUY  = 0;
    uint8 private constant SIDE_SELL = 1;

    // ── decode-only struct ────────────────────────────────────────────────────

    struct _Order {
        address maker;
        address signer;
        address taker;
        uint256 tokenId;
        uint256 makerAmount;
        uint256 takerAmount;
        uint256 salt;
        uint256 expiration;
        uint256 nonce;
        uint256 feeRateBps;
        uint8   side;
        uint8   signatureType;
        bytes   signature;
    }

    // ── state ─────────────────────────────────────────────────────────────────

    address public immutable limitlessExchange;

    mapping(uint256 tokenId => bool) public isAllowedMarket;

    uint256 public maxPositionSize;
    bool    public allowLong;
    bool    public allowShort;
    address public permissionSigner;

    // ── events ────────────────────────────────────────────────────────────────

    event MaxPositionSizeUpdated(uint256 oldSize, uint256 newSize);
    event DirectionUpdated(bool allowLong, bool allowShort);

    // ── errors ────────────────────────────────────────────────────────────────

    error NotPermissionSigner();
    error ZeroAddress();

    // ── modifier ─────────────────────────────────────────────────────────────

    modifier onlyPermissionSigner() {
        if (msg.sender != permissionSigner) revert NotPermissionSigner();
        _;
    }

    // ── constructor ───────────────────────────────────────────────────────────

    constructor(
        address _limitlessExchange,
        uint256[] memory allowedMarketIds,
        uint256 _maxPositionSize,
        bool _allowLong,
        bool _allowShort,
        address _permissionSigner
    ) {
        if (_limitlessExchange == address(0)) revert ZeroAddress();
        if (_permissionSigner  == address(0)) revert ZeroAddress();

        limitlessExchange = _limitlessExchange;
        maxPositionSize   = _maxPositionSize;
        allowLong         = _allowLong;
        allowShort        = _allowShort;
        permissionSigner  = _permissionSigner;

        for (uint256 i; i < allowedMarketIds.length; i++) {
            isAllowedMarket[allowedMarketIds[i]] = true;
        }
    }

    // ── setters ───────────────────────────────────────────────────────────────

    function setMaxPositionSize(uint256 newSize) external onlyPermissionSigner {
        uint256 old = maxPositionSize;
        maxPositionSize = newSize;
        emit MaxPositionSizeUpdated(old, newSize);
    }

    function setDirection(bool _allowLong, bool _allowShort) external onlyPermissionSigner {
        allowLong  = _allowLong;
        allowShort = _allowShort;
        emit DirectionUpdated(_allowLong, _allowShort);
    }

    // ── IPermission ───────────────────────────────────────────────────────────

    /// @inheritdoc IPermission
    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        // Gate 1 — target must be Limitless CTF Exchange
        if (ctx.target != limitlessExchange) return false;

        // Gate 2 — selector must be fillOrder
        if (ctx.selector != FILL_ORDER) return false;

        // Gate 3 — length guard then decode + field checks
        if (txData.length < MIN_CALLDATA_LEN) return false;

        _Order memory order;
        try this._decodeOrder(txData[4:]) returns (_Order memory decoded, uint256) {
            order = decoded;
        } catch {
            return false;
        }

        // maker must be the managed Safe account
        if (order.maker != ctx.account) return false;

        // tokenId must be in the allowed market list
        if (!isAllowedMarket[order.tokenId]) return false;

        // makerAmount (USDC for BUY, conditional tokens for SELL) must not exceed cap
        if (order.makerAmount > maxPositionSize) return false;

        // direction check: BUY = long (buying YES tokens), SELL = short
        if (order.side == SIDE_BUY  && !allowLong)  return false;
        if (order.side == SIDE_SELL && !allowShort) return false;

        return true;
    }

    /// @inheritdoc IPermission
    function discriminator() external pure returns (bytes32) {
        return keccak256("LimitlessPredictionPermission");
    }

    // ── external decode helper (used via try/catch in evaluate) ──────────────

    /// @dev External so it can be called with try/catch for revert-safe decoding.
    function _decodeOrder(bytes calldata data) external pure returns (_Order memory order, uint256 fillAmount) {
        (order, fillAmount) = abi.decode(data, (_Order, uint256));
    }
}
