package com.securebank.service;

import com.securebank.domain.Account;
import com.securebank.domain.Transaction;
import com.securebank.domain.TransactionStatus;
import com.securebank.domain.TransactionType;
import com.securebank.repository.AccountRepository;
import com.securebank.repository.TransactionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;

/**
 * VULNERABILITY: Race Condition in Fund Transfers (CWE-362)
 * No pessimistic locking on account balance checks
 * Multiple concurrent transfers can overdraft an account
 */
@Service
public class TransferService {

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private TransactionRepository transactionRepository;

    @Autowired
    private AuthService authService;

    /**
     * VULNERABILITY: Race Condition (CWE-362)
     * This method reads the account balance, checks it, then updates it
     * WITHOUT any locking mechanism (no pessimistic or optimistic locking)
     *
     * EXPLOIT: Send multiple concurrent transfer requests for the same account
     * Example: Account has $100, send 5 concurrent $80 transfers
     * All 5 will see $100 balance and proceed, resulting in -$300 balance
     *
     * The Thread.sleep() simulates processing time and makes the race condition worse
     */
    @Transactional
    public Transaction processTransfer(Long fromAccountId, Long toAccountId, BigDecimal amount) {
        // VULNERABLE: No locking on these reads!
        Account fromAccount = accountRepository.findById(fromAccountId)
                .orElseThrow(() -> new RuntimeException("From account not found"));

        Account toAccount = accountRepository.findById(toAccountId)
                .orElseThrow(() -> new RuntimeException("To account not found"));

        // Check balance without locking
        if (fromAccount.getBalance().compareTo(amount) < 0) {
            throw new RuntimeException("Insufficient balance");
        }

        // VULNERABILITY: Race condition window - multiple threads can get here simultaneously
        // Simulate processing delay to make race condition more exploitable
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Update balances (multiple threads can do this concurrently)
        fromAccount.setBalance(fromAccount.getBalance().subtract(amount));
        toAccount.setBalance(toAccount.getBalance().add(amount));

        accountRepository.save(fromAccount);
        accountRepository.save(toAccount);

        // Create transaction record
        Transaction transaction = Transaction.builder()
                .fromAccountId(fromAccountId)
                .toAccountId(toAccountId)
                .amount(amount)
                .transactionType(TransactionType.TRANSFER)
                .status(TransactionStatus.COMPLETED)
                .tenantId(fromAccount.getTenantId())
                .description("Transfer from " + fromAccount.getAccountNumber() + " to " + toAccount.getAccountNumber())
                .build();

        return transactionRepository.save(transaction);
    }

    /**
     * Secure version (for comparison) - uses pessimistic locking
     * This is NOT used by default in the vulnerable application
     */
    @Transactional
    public Transaction processTransferSecure(Long fromAccountId, Long toAccountId, BigDecimal amount) {
        // SECURE: Use pessimistic locking
        Account fromAccount = accountRepository.findByIdWithLock(fromAccountId)
                .orElseThrow(() -> new RuntimeException("From account not found"));

        Account toAccount = accountRepository.findByIdWithLock(toAccountId)
                .orElseThrow(() -> new RuntimeException("To account not found"));

        if (fromAccount.getBalance().compareTo(amount) < 0) {
            throw new RuntimeException("Insufficient balance");
        }

        fromAccount.setBalance(fromAccount.getBalance().subtract(amount));
        toAccount.setBalance(toAccount.getBalance().add(amount));

        accountRepository.save(fromAccount);
        accountRepository.save(toAccount);

        Transaction transaction = Transaction.builder()
                .fromAccountId(fromAccountId)
                .toAccountId(toAccountId)
                .amount(amount)
                .transactionType(TransactionType.TRANSFER)
                .status(TransactionStatus.COMPLETED)
                .tenantId(fromAccount.getTenantId())
                .description("Secure transfer from " + fromAccount.getAccountNumber() + " to " + toAccount.getAccountNumber())
                .build();

        return transactionRepository.save(transaction);
    }
}
