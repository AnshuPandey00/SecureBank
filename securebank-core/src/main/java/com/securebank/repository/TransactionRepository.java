package com.securebank.repository;

import com.securebank.domain.Transaction;
import com.securebank.domain.TransactionStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface TransactionRepository extends JpaRepository<Transaction, Long> {

    List<Transaction> findByFromAccountId(Long fromAccountId);

    List<Transaction> findByToAccountId(Long toAccountId);

    List<Transaction> findByFromAccountIdOrToAccountId(Long fromAccountId, Long toAccountId);

    List<Transaction> findByFromAccountIdAndTenantId(Long fromAccountId, Long tenantId);

    List<Transaction> findByStatus(TransactionStatus status);

    @Query("SELECT t FROM Transaction t WHERE t.fromAccountId = :accountId OR t.toAccountId = :accountId ORDER BY t.createdAt DESC")
    List<Transaction> findAccountTransactions(@Param("accountId") Long accountId);

    @Query("SELECT t FROM Transaction t WHERE (t.fromAccountId = :accountId OR t.toAccountId = :accountId) AND t.tenantId = :tenantId ORDER BY t.createdAt DESC")
    List<Transaction> findAccountTransactionsByTenant(@Param("accountId") Long accountId, @Param("tenantId") Long tenantId);

    List<Transaction> findByCreatedAtBetween(LocalDateTime start, LocalDateTime end);

    /**
     * VULNERABILITY: Tenant Isolation Failure (CWE-566)
     * Returns all transactions across all tenants
     */
    @Override
    List<Transaction> findAll();
}
