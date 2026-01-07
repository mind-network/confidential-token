// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.27;

import {euint64, externalEuint64} from "@fhevm/solidity/lib/FHE.sol";

interface IFHEToken {
    struct ConfidentialPayment {
        address holder;
        address payee;
        uint256 maxClearAmount;
        bytes32 resourceHash;
        uint48 validAfter;
        uint48 validBefore;
        bytes32 nonce;
        bytes32 encryptedAmountHash;
    }

    function confidentialTransferWithAuthorization(
        ConfidentialPayment calldata p,
        externalEuint64 encryptedAmountInput,
        bytes calldata inputProof,
        bytes calldata sig
    ) external returns (euint64 transferred);
}

contract FHETokenBatcher {
    struct Request {
        IFHEToken.ConfidentialPayment p;
        externalEuint64 encryptedAmountInput;
        bytes inputProof;
        bytes sig;
    }

    event BatchItemSuccess(uint256 indexed index, bytes32 transferredHandle);
    event BatchItemFailure(uint256 indexed index, bytes reason);

    function batchConfidentialTransferWithAuthorization(
        address token,
        Request[] calldata requests
    ) external returns (bool[] memory successes, bytes32[] memory transferredHandles) {
        uint256 length = requests.length;
        successes = new bool[](length);
        transferredHandles = new bytes32[](length);

        for (uint256 i = 0; i < length; i++) {
            Request calldata req = requests[i];
            try
                IFHEToken(token).confidentialTransferWithAuthorization(
                    req.p,
                    req.encryptedAmountInput,
                    req.inputProof,
                    req.sig
                )
            returns (euint64 transferred) {
                successes[i] = true;
                transferredHandles[i] = euint64.unwrap(transferred);
                emit BatchItemSuccess(i, transferredHandles[i]);
            } catch (bytes memory reason) {
                emit BatchItemFailure(i, reason);
            }
        }
    }
}
