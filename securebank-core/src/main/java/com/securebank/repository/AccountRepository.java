package com.securebank.repository;

import com.securebank.domain.Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;

@Repository
public interface AccountRepository extends JpaRepository<Account, Long> {

    Optional<Account> findByAccountNumber(String accountNumber);

    List<Account> findByUserId(Long userId);

    List<Account> findByUserIdAndTenantId(Long userId, Long tenantId);

    /**
     * VULNERABILITY: Tenant Isolation Failure (CWE-566)
     * This method returns ALL accounts across all tenants
     * Should filter by tenantId
     */
    @Override
    List<Account> findAll();

    List<Account> findByTenantId(Long tenantId);

    /**
     * Method WITH proper locking (for comparison with vulnerable version)
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT a FROM Account a WHERE a.id = :id")
    Optional<Account> findByIdWithLock(@Param("id") Long id);
}
