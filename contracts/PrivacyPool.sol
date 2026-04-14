// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

interface IPaymentGateway {
    function payInvoice(bytes32 invoiceId) external returns (address merchant);
    function getAmount(bytes32 invoiceId) external view returns (uint256);
    function getToken(bytes32 invoiceId) external view returns (address);
}

interface IVerifier {
    function verifyProof(
        uint256[2]    calldata a,
        uint256[2][2] calldata b,
        uint256[2]    calldata c,
        uint256[3]    calldata input
    ) external view returns (bool);
}

contract PrivacyPool is ReentrancyGuard, Ownable {
    using SafeERC20 for IERC20;

    error AlreadySpent();
    error InvalidInput();
    error UnsupportedToken();
    error NotRelayer();
    error InvalidProof();
    error DuplicateCommitment();
    error GatewayNotSet();

    IPaymentGateway public paymentGateway;
    IVerifier       public immutable verifier;
    address         public relayer;

    mapping(address => bool) public supportedTokens;

    struct Commitment {
        address depositor;
        address token;
        uint256 amount;
        bool    exists;
    }

    mapping(bytes32 => Commitment) private commitments;
    mapping(bytes32 => bool)       private nullifiers;

    event TokenAdded(address indexed token);
    event TokenRemoved(address indexed token);
    event RelayerUpdated(address indexed newRelayer);
    event GatewayUpdated(address indexed newGateway);
    event Deposited(bytes32 indexed commitment, address indexed depositor, address indexed token, uint256 amount);
    event WithdrawalRelayed(bytes32 indexed nullifier, bytes32 indexed invoiceId, address indexed merchant, address token, uint256 amount);

    constructor(
        address _paymentGateway,
        address _verifier,
        address _relayer,
        address _usdc,
        address _hsk
    ) Ownable(msg.sender) {
        require(_verifier != address(0), "Invalid verifier");
        require(_relayer  != address(0), "Invalid relayer");

        if (_paymentGateway != address(0)) {
            paymentGateway = IPaymentGateway(_paymentGateway);
        }

        verifier = IVerifier(_verifier);
        relayer  = _relayer;

        if (_usdc != address(0)) { supportedTokens[_usdc] = true; emit TokenAdded(_usdc); }
        if (_hsk  != address(0)) { supportedTokens[_hsk]  = true; emit TokenAdded(_hsk);  }
    }

    function setPaymentGateway(address _gateway) external onlyOwner {
        require(_gateway != address(0), "Invalid gateway");
        paymentGateway = IPaymentGateway(_gateway);
        emit GatewayUpdated(_gateway);
    }

    function addToken(address token) external onlyOwner {
        require(token != address(0), "Invalid token");
        supportedTokens[token] = true;
        emit TokenAdded(token);
    }

    function removeToken(address token) external onlyOwner {
        supportedTokens[token] = false;
        emit TokenRemoved(token);
    }

    function updateRelayer(address newRelayer) external onlyOwner {
        require(newRelayer != address(0), "Invalid relayer");
        relayer = newRelayer;
        emit RelayerUpdated(newRelayer);
    }

    function deposit(
        address token,
        bytes32 commitment,
        uint256 amount
    ) external nonReentrant {
        if (!supportedTokens[token])        revert UnsupportedToken();
        if (commitment == bytes32(0))       revert InvalidInput();
        if (amount == 0)                    revert InvalidInput();
        if (commitments[commitment].exists) revert DuplicateCommitment();

        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        commitments[commitment] = Commitment({
            depositor: msg.sender,
            token:     token,
            amount:    amount,
            exists:    true
        });

        emit Deposited(commitment, msg.sender, token, amount);
    }

    function withdrawAndPay(
        bytes32       nullifier,
        bytes32       invoiceId,
        uint256[2]    calldata a,
        uint256[2][2] calldata b,
        uint256[2]    calldata c,
        uint256[3]    calldata publicSignals
    ) external nonReentrant {
        if (address(paymentGateway) == address(0)) revert GatewayNotSet();
        if (msg.sender != relayer)                 revert NotRelayer();
        if (nullifier  == bytes32(0))              revert InvalidInput();
        if (invoiceId  == bytes32(0))              revert InvalidInput();
        if (nullifiers[nullifier])                 revert AlreadySpent();

        if (!verifier.verifyProof(a, b, c, publicSignals)) revert InvalidProof();

        nullifiers[nullifier] = true;

        address token    = paymentGateway.getToken(invoiceId);
        uint256 amount   = paymentGateway.getAmount(invoiceId);
        address merchant = paymentGateway.payInvoice(invoiceId);

        if (!supportedTokens[token]) revert UnsupportedToken();

        IERC20(token).safeTransfer(merchant, amount);

        emit WithdrawalRelayed(nullifier, invoiceId, merchant, token, amount);
    }

    function isSpent(bytes32 nullifier) external view returns (bool) {
        return nullifiers[nullifier];
    }

    function getCommitment(bytes32 commitment) external view returns (
        address depositor,
        address token,
        uint256 amount,
        bool    exists
    ) {
        Commitment storage c = commitments[commitment];
        return (c.depositor, c.token, c.amount, c.exists);
    }

    function poolBalance(address token) external view returns (uint256) {
        return IERC20(token).balanceOf(address(this));
    }
}
