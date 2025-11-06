package com.securebank.controller;

import com.securebank.domain.Transaction;
import com.securebank.service.TransactionService;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * VULNERABILITY: SQL Injection (CWE-89)
 * The search endpoint uses string concatenation to build SQL queries
 */
@RestController
@RequestMapping("/api/transactions")
public class TransactionController {

    @Autowired
    private TransactionService transactionService;

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * VULNERABILITY: SQL Injection (CWE-89)
     * User input is directly concatenated into SQL query without any sanitization
     *
     * EXPLOIT: /api/transactions/search?query=test' OR '1'='1
     * This will return all transactions in the database
     *
     * More advanced exploit:
     * /api/transactions/search?query=test' UNION SELECT id,from_account_id,to_account_id,amount,'hacked' as description,transaction_type,status,tenant_id,created_at,updated_at FROM transactions--
     */
    @GetMapping("/search")
    public ResponseEntity<?> searchTransactions(@RequestParam String query) {
        try {
            // VULNERABLE: String concatenation with user input!
            String sql = "SELECT * FROM transactions WHERE description LIKE '%" + query + "%'";

            @SuppressWarnings("unchecked")
            List<Transaction> transactions = entityManager.createNativeQuery(sql, Transaction.class)
                    .getResultList();

            return ResponseEntity.ok(transactions);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getTransaction(@PathVariable Long id) {
        try {
            Transaction transaction = transactionService.getTransactionById(id);
            return ResponseEntity.ok(transaction);
        } catch (Exception e) {
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/all")
    public ResponseEntity<?> getAllTransactions() {
        // VULNERABILITY: Tenant isolation failure
        List<Transaction> transactions = transactionService.getAllTransactions();
        return ResponseEntity.ok(transactions);
    }
}
