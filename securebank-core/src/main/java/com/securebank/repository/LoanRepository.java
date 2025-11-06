package com.securebank.repository;

import com.securebank.domain.Loan;
import com.securebank.domain.LoanStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface LoanRepository extends JpaRepository<Loan, Long> {

    List<Loan> findByUserId(Long userId);

    List<Loan> findByUserIdAndTenantId(Long userId, Long tenantId);

    List<Loan> findByStatus(LoanStatus status);

    List<Loan> findByStatusAndTenantId(LoanStatus status, Long tenantId);

    List<Loan> findByTenantId(Long tenantId);

    /**
     * VULNERABILITY: Tenant Isolation Failure (CWE-566)
     * Returns all loans across all tenants
     */
    @Override
    List<Loan> findAll();
}
