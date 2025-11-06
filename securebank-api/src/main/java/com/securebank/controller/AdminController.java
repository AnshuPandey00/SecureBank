package com.securebank.controller;

import com.securebank.domain.AuditLog;
import com.securebank.repository.UserRepository;
import com.securebank.service.AuditService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuditService auditService;

    /**
     * VULNERABILITY: Tenant Isolation Failure
     * Returns all users across all tenants
     */
    @GetMapping("/users")
    public ResponseEntity<?> getAllUsers() {
        return ResponseEntity.ok(userRepository.findAll());
    }

    @GetMapping("/audit-logs")
    public ResponseEntity<?> getAuditLogs() {
        List<AuditLog> logs = auditService.getAuditLogs();
        return ResponseEntity.ok(logs);
    }

    @GetMapping("/audit-logs/user/{userId}")
    public ResponseEntity<?> getUserAuditLogs(@PathVariable Long userId) {
        List<AuditLog> logs = auditService.getUserAuditLogs(userId);
        return ResponseEntity.ok(logs);
    }
}
