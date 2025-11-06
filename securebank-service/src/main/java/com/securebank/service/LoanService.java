package com.securebank.service;

import com.securebank.domain.Loan;
import com.securebank.domain.LoanStatus;
import com.securebank.repository.LoanRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class LoanService {

    @Autowired
    private LoanRepository loanRepository;

    @Autowired
    private AuthService authService;

    /**
     * VULNERABILITY: Mass Assignment (CWE-915)
     * This method saves a Loan entity directly from user input
     * Attacker can set status=APPROVED and approvedBy fields
     * Should use a DTO and only set allowed fields
     */
    @Transactional
    public Loan applyForLoan(Loan loan) {
        // Set the user ID from authenticated user
        loan.setUserId(authService.getCurrentUserId());
        loan.setTenantId(authService.getCurrentTenantId());

        // VULNERABILITY: We don't override status and approvedBy here
        // If the attacker sends {"status": "APPROVED", "approvedBy": 1} in JSON,
        // it will be bound to the Loan object and saved!

        return loanRepository.save(loan);
    }

    @Transactional
    public Loan approveLoan(Long loanId, Long managerId) {
        Loan loan = loanRepository.findById(loanId)
                .orElseThrow(() -> new RuntimeException("Loan not found"));

        loan.setStatus(LoanStatus.APPROVED);
        loan.setApprovedBy(managerId);

        return loanRepository.save(loan);
    }

    @Transactional
    public Loan rejectLoan(Long loanId) {
        Loan loan = loanRepository.findById(loanId)
                .orElseThrow(() -> new RuntimeException("Loan not found"));

        loan.setStatus(LoanStatus.REJECTED);

        return loanRepository.save(loan);
    }

    public List<Loan> getUserLoans(Long userId) {
        return loanRepository.findByUserId(userId);
    }

    public List<Loan> getCurrentUserLoans() {
        Long userId = authService.getCurrentUserId();
        Long tenantId = authService.getCurrentTenantId();
        return loanRepository.findByUserIdAndTenantId(userId, tenantId);
    }

    public List<Loan> getPendingLoans() {
        Long tenantId = authService.getCurrentTenantId();
        return loanRepository.findByStatusAndTenantId(LoanStatus.PENDING, tenantId);
    }

    public Loan getLoanById(Long id) {
        return loanRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Loan not found"));
    }
}
