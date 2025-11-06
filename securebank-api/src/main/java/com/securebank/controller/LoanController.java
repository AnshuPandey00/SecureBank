package com.securebank.controller;

import com.securebank.domain.Loan;
import com.securebank.service.AuditService;
import com.securebank.service.AuthService;
import com.securebank.service.LoanService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * VULNERABILITY: Mass Assignment (CWE-915)
 * The apply endpoint accepts a Loan entity directly, allowing attackers
 * to set fields like status, approvedBy that should be restricted
 */
@RestController
@RequestMapping("/api/loans")
public class LoanController {

    @Autowired
    private LoanService loanService;

    @Autowired
    private AuthService authService;

    @Autowired
    private AuditService auditService;

    /**
     * VULNERABILITY: Mass Assignment (CWE-915)
     * Accepts @RequestBody Loan directly without using a DTO
     * Attacker can set status=APPROVED, approvedBy=X in the JSON request
     *
     * EXPLOIT: POST /api/loans/apply
     * Body: {
     *   "amount": 10000,
     *   "interestRate": 5.0,
     *   "termMonths": 12,
     *   "status": "APPROVED",    <-- MALICIOUS
     *   "approvedBy": 1          <-- MALICIOUS
     * }
     *
     * This will create a pre-approved loan without manager review!
     */
    @PostMapping("/apply")
    public ResponseEntity<?> applyForLoan(@RequestBody Loan loan) {
        try {
            // VULNERABLE: Loan object can have status and approvedBy already set!
            Loan savedLoan = loanService.applyForLoan(loan);

            auditService.logAction("LOAN_APPLICATION", "Loan", savedLoan.getId(),
                    "SUCCESS", "Applied for loan of " + loan.getAmount());

            return ResponseEntity.ok(savedLoan);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Loan application failed: " + e.getMessage());
        }
    }

    @PostMapping("/{id}/approve")
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN')")
    public ResponseEntity<?> approveLoan(@PathVariable Long id) {
        try {
            Long managerId = authService.getCurrentUserId();
            Loan loan = loanService.approveLoan(id, managerId);

            auditService.logAction("LOAN_APPROVAL", "Loan", id,
                    "SUCCESS", "Loan approved by manager " + managerId);

            return ResponseEntity.ok(loan);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Loan approval failed: " + e.getMessage());
        }
    }

    @PostMapping("/{id}/reject")
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN')")
    public ResponseEntity<?> rejectLoan(@PathVariable Long id) {
        try {
            Loan loan = loanService.rejectLoan(id);

            auditService.logAction("LOAN_REJECTION", "Loan", id,
                    "SUCCESS", "Loan rejected");

            return ResponseEntity.ok(loan);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Loan rejection failed: " + e.getMessage());
        }
    }

    @GetMapping("/my-loans")
    public ResponseEntity<?> getMyLoans() {
        List<Loan> loans = loanService.getCurrentUserLoans();
        return ResponseEntity.ok(loans);
    }

    @GetMapping("/pending")
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN')")
    public ResponseEntity<?> getPendingLoans() {
        List<Loan> loans = loanService.getPendingLoans();
        return ResponseEntity.ok(loans);
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getLoan(@PathVariable Long id) {
        try {
            Loan loan = loanService.getLoanById(id);
            return ResponseEntity.ok(loan);
        } catch (Exception e) {
            return ResponseEntity.notFound().build();
        }
    }
}
