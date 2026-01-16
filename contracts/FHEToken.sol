// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.27;

import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {FHE, euint32, euint64, externalEuint32, externalEuint64} from "@fhevm/solidity/lib/FHE.sol";
import {ERC7984} from "@openzeppelin/confidential-contracts/token/ERC7984/ERC7984.sol";
import {
    ERC7984ERC20Wrapper
} from "@openzeppelin/confidential-contracts/token/ERC7984/extensions/ERC7984ERC20Wrapper.sol";
import {
    ERC7984ObserverAccess
} from "@openzeppelin/confidential-contracts/token/ERC7984/extensions/ERC7984ObserverAccess.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract FHEToken is ZamaEthereumConfig, ERC7984ObserverAccess, ERC7984ERC20Wrapper, EIP712 {
    using ECDSA for bytes32;

    error NonceAlreadyUsed();
    error InvalidHolder();
    error InvalidPayee();
    error InvalidRecipient();
    error NotYetValid();
    error AuthorizationExpired();
    error EncryptedAmountMismatch();
    error InvalidSignature();

    // ====== EIP-712 Typed Data ======

    /// @dev Payment authorization struct
    /// @notice
    /// - maxClearAmount: Optional “maximum clear amount”, only for off-chain risk control/display; ignored on-chain
    /// - resourceHash: Resource identifier (keccak256(resourceUrl or other id))
    /// - encryptedAmountHash: keccak256(abi.encode(handle)) of the externalEuint64 input handle
    struct ConfidentialPayment {
        address holder; // Payer (token holder)
        address payee; // Recipient
        uint256 maxClearAmount; // Optional: maximum clear amount (e.g., quoted price). Use 0 if sensitive.
        bytes32 resourceHash; // Resource/order identifier
        uint48 validAfter; // Start of validity window (unix seconds)
        uint48 validBefore; // Expiration time (unix seconds)
        bytes32 nonce; // Replay-protection nonce
        bytes32 encryptedAmountHash; // Hash of the encrypted amount handle
    }

    /// @dev Unwrap authorization struct (for FHEToken -> underlying unwrap)
    struct UnwrapAuthorization {
        address holder; // FHEToken holder
        address to; // Recipient of underlying
        uint48 validAfter; // Start of validity window (unix seconds)
        uint48 validBefore; // Expiration time (unix seconds)
        bytes32 nonce; // Replay-protection nonce
        bytes32 encryptedAmountHash; // Hash of the encrypted amount handle
    }

    bytes32 public constant CONFIDENTIAL_PAYMENT_TYPEHASH =
        keccak256(
            "ConfidentialPayment("
            "address holder,"
            "address payee,"
            "uint256 maxClearAmount,"
            "bytes32 resourceHash,"
            "uint48 validAfter,"
            "uint48 validBefore,"
            "bytes32 nonce,"
            "bytes32 encryptedAmountHash"
            ")"
        );

    bytes32 public constant UNWRAP_AUTHORIZATION_TYPEHASH =
        keccak256(
            "UnwrapAuthorization("
            "address holder,"
            "address to,"
            "uint48 validAfter,"
            "uint48 validBefore,"
            "bytes32 nonce,"
            "bytes32 encryptedAmountHash"
            ")"
        );

    /// @dev Replay protection: each (holder, nonce) pair can be used only once
    mapping(address => mapping(bytes32 => bool)) public usedNonces;
    mapping(euint64 unwrapAmount => address recipient) private _authUnwrapRequests;

    /// @dev Payment execution event (only emits the euint64 handle, not the plaintext amount)
    event ConfidentialPaymentExecuted(
        address indexed holder,
        address indexed payee,
        uint256 maxClearAmount,
        bytes32 indexed resourceHash,
        bytes32 nonce,
        euint64 transferredAmount
    );

    event UnwrapWithAuthorizationExecuted(
        address indexed holder,
        address indexed to,
        bytes32 nonce,
        bytes32 encryptedAmountHandle
    );

    constructor(
        string memory name_,
        string memory symbol_,
        string memory contractURI_,
        IERC20 underlying_
    ) ERC7984(name_, symbol_, contractURI_) ERC7984ERC20Wrapper(underlying_) EIP712(name_, "1") {}

    // ====== EIP-712 hash helpers ======

    function _hashPayment(ConfidentialPayment calldata p) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    CONFIDENTIAL_PAYMENT_TYPEHASH,
                    p.holder,
                    p.payee,
                    p.maxClearAmount,
                    p.resourceHash,
                    p.validAfter,
                    p.validBefore,
                    p.nonce,
                    p.encryptedAmountHash
                )
            );
    }

    function _hashUnwrap(UnwrapAuthorization calldata p) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    UNWRAP_AUTHORIZATION_TYPEHASH,
                    p.holder,
                    p.to,
                    p.validAfter,
                    p.validBefore,
                    p.nonce,
                    p.encryptedAmountHash
                )
            );
    }

    function _useNonce(address holder, bytes32 nonce) internal {
        if (usedNonces[holder][nonce]) {
            revert NonceAlreadyUsed();
        }
        usedNonces[holder][nonce] = true;
    }

    // ====== External: EIP-712 authorization + confidential transfer ======

    /// @notice Execute a confidential payment using the holder’s EIP-712 signature
    /// @param p Payment authorization struct (typed data)
    /// @param encryptedAmountInput externalEuint64 handle generated by the fhEVM SDK
    /// @param inputProof           fhEVM input proof
    /// @param sig                  Holder’s EIP-712 signature over the typed data
    ///
    /// @dev Flow:
    ///  1. Validate time window and nonce
    ///  2. Ensure encryptedAmountInput matches p.encryptedAmountHash
    ///  3. Recover signer via EIP-712 and require signer == p.holder
    ///  4. Convert to euint64 via FHE.fromExternal(...)
    ///  5. Use ERC7984 internal _transfer to move confidential balance from holder to payee
    ///
    /// @return transferred Encrypted amount handle that was transferred
    function confidentialTransferWithAuthorization(
        ConfidentialPayment calldata p,
        externalEuint64 encryptedAmountInput,
        bytes calldata inputProof,
        bytes calldata sig
    ) external returns (euint64 transferred) {
        // --- Basic checks ---

        if (p.holder == address(0)) {
            revert InvalidHolder();
        }
        if (p.payee == address(0)) {
            revert InvalidPayee();
        }

        // Validity window
        uint48 blockTs = uint48(block.timestamp);
        if (blockTs < p.validAfter) {
            revert NotYetValid();
        }
        if (blockTs > p.validBefore) {
            revert AuthorizationExpired();
        }

        // Nonce replay protection
        _useNonce(p.holder, p.nonce);

        // Bind the encrypted amount handle to prevent ciphertext substitution
        if (keccak256(abi.encode(encryptedAmountInput)) != p.encryptedAmountHash) {
            revert EncryptedAmountMismatch();
        }

        // --- Recover signature ---

        bytes32 digest = _hashTypedDataV4(_hashPayment(p));
        if (ECDSA.recover(digest, sig) != p.holder) {
            revert InvalidSignature();
        }

        // --- Confidential transfer ---

        // Convert externalEuint64 + inputProof into a usable euint64.
        // Note: FHE.fromExternal authorizes this ciphertext to the current contract in the fhEVM ACL.
        // Use ERC7984 internal _transfer to move confidential balance from holder to payee.
        // _transfer does not enforce EOA/operator checks; this contract guards via signatures.
        transferred = _transfer(p.holder, p.payee, FHE.fromExternal(encryptedAmountInput, inputProof));

        emit ConfidentialPaymentExecuted(p.holder, p.payee, p.maxClearAmount, p.resourceHash, p.nonce, transferred);
    }

    /// @notice Unwrap FHEToken into underlying using holder’s EIP-712 signature
    /// @param p Unwrap authorization struct (typed data)
    /// @param encryptedAmountInput externalEuint64 handle generated by the fhEVM SDK
    /// @param inputProof           fhEVM input proof
    /// @param sig                  Holder’s EIP-712 signature over the typed data
    ///
    /// @dev Note: this function bypasses operator checks; authorization is enforced by the signature.
    function unwrapWithAuthorization(
        UnwrapAuthorization calldata p,
        externalEuint64 encryptedAmountInput,
        bytes calldata inputProof,
        bytes calldata sig
    ) external {
        if (p.holder == address(0)) {
            revert InvalidHolder();
        }
        if (p.to == address(0)) {
            revert InvalidRecipient();
        }

        uint48 blockTs = uint48(block.timestamp);
        if (blockTs < p.validAfter) {
            revert NotYetValid();
        }
        if (blockTs > p.validBefore) {
            revert AuthorizationExpired();
        }

        _useNonce(p.holder, p.nonce);

        if (keccak256(abi.encode(encryptedAmountInput)) != p.encryptedAmountHash) {
            revert EncryptedAmountMismatch();
        }

        bytes32 digest = _hashTypedDataV4(_hashUnwrap(p));
        if (ECDSA.recover(digest, sig) != p.holder) {
            revert InvalidSignature();
        }

        euint64 amount = FHE.fromExternal(encryptedAmountInput, inputProof);
        euint64 burntAmount = _burn(p.holder, amount);
        FHE.makePubliclyDecryptable(burntAmount);

        assert(_authUnwrapRequests[burntAmount] == address(0));
        _authUnwrapRequests[burntAmount] = p.to;

        emit UnwrapRequested(p.to, burntAmount);

        emit UnwrapWithAuthorizationExecuted(p.holder, p.to, p.nonce, euint64.unwrap(burntAmount));
    }

    function finalizeUnwrap(
        euint64 burntAmount,
        uint64 burntAmountCleartext,
        bytes calldata decryptionProof
    ) public override {
        address to = _authUnwrapRequests[burntAmount];
        if (to == address(0)) {
            super.finalizeUnwrap(burntAmount, burntAmountCleartext, decryptionProof);
            return;
        }
        delete _authUnwrapRequests[burntAmount];

        bytes32[] memory handles = new bytes32[](1);
        handles[0] = euint64.unwrap(burntAmount);

        bytes memory cleartexts = abi.encode(burntAmountCleartext);

        FHE.checkSignatures(handles, cleartexts, decryptionProof);

        SafeERC20.safeTransfer(underlying(), to, burntAmountCleartext * rate());

        emit UnwrapFinalized(to, burntAmount, burntAmountCleartext);
    }

    function decimals() public view override(ERC7984, ERC7984ERC20Wrapper) returns (uint8) {
        return ERC7984ERC20Wrapper.decimals();
    }

    function _update(
        address from,
        address to,
        euint64 amount
    ) internal override(ERC7984ObserverAccess, ERC7984ERC20Wrapper) returns (euint64 transferred) {
        return ERC7984ObserverAccess._update(from, to, amount);
    }
}
