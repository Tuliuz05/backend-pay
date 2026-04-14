// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PaymentGateway {

    error InvoiceExists();
    error InvoiceNotFound();
    error AlreadyPaid();
    error InvalidAmount();
    error NotAuthorized();
    error InvalidToken();

    struct Invoice {
        address merchant;
        address token;
        uint256 amount;
        bool    paid;
        bool    exists;
    }

    mapping(bytes32 => Invoice) private invoices;
    address public immutable privacyPool;

    event InvoiceCreated(bytes32 indexed invoiceId, address indexed merchant, address token, uint256 amount);
    event InvoicePaid(bytes32 indexed invoiceId, address indexed merchant, address token, uint256 amount);

    constructor(address _privacyPool) {
        require(_privacyPool != address(0), "Invalid pool");
        privacyPool = _privacyPool;
    }

    function createInvoice(bytes32 invoiceId, address token, uint256 amount) external {
        if (invoices[invoiceId].exists) revert InvoiceExists();
        if (amount == 0)               revert InvalidAmount();
        if (token == address(0))       revert InvalidToken();

        invoices[invoiceId] = Invoice({
            merchant: msg.sender,
            token:    token,
            amount:   amount,
            paid:     false,
            exists:   true
        });

        emit InvoiceCreated(invoiceId, msg.sender, token, amount);
    }

    function payInvoice(bytes32 invoiceId) external returns (address merchant) {
        if (msg.sender != privacyPool)    revert NotAuthorized();
        if (!invoices[invoiceId].exists)  revert InvoiceNotFound();
        if (invoices[invoiceId].paid)     revert AlreadyPaid();

        invoices[invoiceId].paid = true;
        merchant = invoices[invoiceId].merchant;

        emit InvoicePaid(invoiceId, merchant, invoices[invoiceId].token, invoices[invoiceId].amount);
    }

    function getInvoice(bytes32 invoiceId) external view returns (
        address merchant, address token, uint256 amount, bool paid, bool exists
    ) {
        Invoice storage inv = invoices[invoiceId];
        return (inv.merchant, inv.token, inv.amount, inv.paid, inv.exists);
    }

    function getAmount(bytes32 invoiceId) external view returns (uint256) {
        if (!invoices[invoiceId].exists) revert InvoiceNotFound();
        return invoices[invoiceId].amount;
    }

    function getToken(bytes32 invoiceId) external view returns (address) {
        if (!invoices[invoiceId].exists) revert InvoiceNotFound();
        return invoices[invoiceId].token;
    }

    function getMerchant(bytes32 invoiceId) external view returns (address) {
        if (!invoices[invoiceId].exists) revert InvoiceNotFound();
        return invoices[invoiceId].merchant;
    }

    function isPaid(bytes32 invoiceId) external view returns (bool) {
        return invoices[invoiceId].paid;
    }
}
