package com.securebank.controller;

import com.securebank.domain.Account;
import com.securebank.domain.AccountType;
import com.securebank.domain.Transaction;
import com.securebank.service.AccountService;
import com.securebank.service.AuthService;
import com.securebank.service.TransactionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * VULNERABILITY: Insecure Direct Object Reference (IDOR) - CWE-639
 * This controller allows users to access any account by ID without authorization checks
 */
@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    @Autowired
    private AccountService accountService;

    @Autowired
    private TransactionService transactionService;

    @Autowired
    private AuthService authService;

    @PostMapping
    public ResponseEntity<?> createAccount(@RequestBody CreateAccountRequest request) {
        Long userId = authService.getCurrentUserId();
        Long tenantId = authService.getCurrentTenantId();

        Account account = accountService.createAccount(userId, request.getAccountType(), tenantId);
        return ResponseEntity.ok(account);
    }

    /**
     * VULNERABILITY: Insecure Direct Object Reference (IDOR) - CWE-639
     * No authorization check to verify the account belongs to the current user!
     *
     * EXPLOIT: User A can access User B's account by changing the ID in the URL
     * Example: GET /api/accounts/123 (where 123 is another user's account)
     */
    @GetMapping("/{id}")
    public ResponseEntity<?> getAccount(@PathVariable Long id) {
        try {
            // VULNERABLE: No check if this account belongs to the authenticated user!
            Account account = accountService.getAccountById(id);
            return ResponseEntity.ok(account);
        } catch (Exception e) {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * VULNERABILITY: Insecure Direct Object Reference (IDOR) - CWE-639
     * No authorization check to verify the account belongs to the current user!
     */
    @GetMapping("/{id}/transactions")
    public ResponseEntity<?> getAccountTransactions(@PathVariable Long id) {
        try {
            // VULNERABLE: No check if this account belongs to the authenticated user!
            List<Transaction> transactions = transactionService.getAccountTransactions(id);
            return ResponseEntity.ok(transactions);
        } catch (Exception e) {
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/my-accounts")
    public ResponseEntity<?> getMyAccounts() {
        List<Account> accounts = accountService.getCurrentUserAccounts();
        return ResponseEntity.ok(accounts);
    }

    // DTO
    public static class CreateAccountRequest {
        private AccountType accountType;

        public AccountType getAccountType() { return accountType; }
        public void setAccountType(AccountType accountType) { this.accountType = accountType; }
    }
}
