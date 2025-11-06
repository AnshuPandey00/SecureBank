package com.securebank.service;

import com.securebank.domain.Transaction;
import com.securebank.repository.TransactionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class TransactionService {

    @Autowired
    private TransactionRepository transactionRepository;

    @Autowired
    private AuthService authService;

    public List<Transaction> getAccountTransactions(Long accountId) {
        Long tenantId = authService.getCurrentTenantId();
        return transactionRepository.findAccountTransactionsByTenant(accountId, tenantId);
    }

    public Transaction getTransactionById(Long id) {
        return transactionRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Transaction not found"));
    }

    /**
     * VULNERABILITY: Tenant Isolation Failure (CWE-566)
     * Returns all transactions across all tenants
     */
    public List<Transaction> getAllTransactions() {
        return transactionRepository.findAll();
    }
}
