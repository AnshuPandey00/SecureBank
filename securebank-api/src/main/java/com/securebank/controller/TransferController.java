package com.securebank.controller;

import com.securebank.domain.Transaction;
import com.securebank.service.AuditService;
import com.securebank.service.TransferService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;

/**
 * VULNERABILITY: Race Condition (CWE-362) in fund transfers
 * VULNERABILITY: CSRF (CWE-352) - no CSRF protection
 * VULNERABILITY: Payment Amount Tampering (CWE-472) - trusts client-provided amount
 */
@RestController
@RequestMapping("/api/transfers")
public class TransferController {

    @Autowired
    private TransferService transferService;

    @Autowired
    private AuditService auditService;

    /**
     * VULNERABILITY: Race Condition (CWE-362)
     * Multiple concurrent requests can overdraft the account
     *
     * VULNERABILITY: CSRF (CWE-352)
     * No CSRF protection - malicious site can submit this form
     *
     * VULNERABILITY: Payment Amount Tampering (CWE-472)
     * Amount comes directly from client and is trusted
     *
     * EXPLOIT for Race Condition:
     * Send 5-10 concurrent POST requests with same fromAccountId
     * All will pass balance check and execute, overdrafting the account
     */
    @PostMapping("/domestic")
    public ResponseEntity<?> domesticTransfer(@RequestBody TransferRequest request) {
        try {
            // VULNERABLE: No CSRF check, race condition in service, trusts client amount
            Transaction transaction = transferService.processTransfer(
                    request.getFromAccountId(),
                    request.getToAccountId(),
                    request.getAmount()
            );

            auditService.logAction("TRANSFER", "Transaction", transaction.getId(),
                    "SUCCESS", "Domestic transfer of " + request.getAmount());

            return ResponseEntity.ok(transaction);
        } catch (Exception e) {
            auditService.logAction("TRANSFER", "Transaction", null,
                    "FAILED", "Transfer failed: " + e.getMessage());
            return ResponseEntity.badRequest().body("Transfer failed: " + e.getMessage());
        }
    }

    @PostMapping("/wire")
    public ResponseEntity<?> wireTransfer(@RequestBody TransferRequest request) {
        try {
            // Same vulnerabilities as domestic transfer
            Transaction transaction = transferService.processTransfer(
                    request.getFromAccountId(),
                    request.getToAccountId(),
                    request.getAmount()
            );

            auditService.logAction("WIRE_TRANSFER", "Transaction", transaction.getId(),
                    "SUCCESS", "Wire transfer of " + request.getAmount());

            return ResponseEntity.ok(transaction);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Wire transfer failed: " + e.getMessage());
        }
    }

    // DTO
    public static class TransferRequest {
        private Long fromAccountId;
        private Long toAccountId;
        private BigDecimal amount;

        public Long getFromAccountId() { return fromAccountId; }
        public void setFromAccountId(Long fromAccountId) { this.fromAccountId = fromAccountId; }
        public Long getToAccountId() { return toAccountId; }
        public void setToAccountId(Long toAccountId) { this.toAccountId = toAccountId; }
        public BigDecimal getAmount() { return amount; }
        public void setAmount(BigDecimal amount) { this.amount = amount; }
    }
}
