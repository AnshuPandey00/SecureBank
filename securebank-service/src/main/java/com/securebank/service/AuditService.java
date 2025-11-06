package com.securebank.service;

import com.securebank.domain.AuditLog;
import com.securebank.repository.AuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;
import java.util.List;

/**
 * VULNERABILITY: Audit Log Tampering (CWE-778)
 * User ID is taken directly from the authenticated principal (JWT claims)
 * which can be manipulated if JWT validation is bypassed or weak
 */
@Service
public class AuditService {

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private AuthService authService;

    /**
     * VULNERABILITY: Audit Log Tampering (CWE-778)
     * The userId comes from JWT claims which can be manipulated
     * If JWT algorithm confusion attack is used, attacker can set any userId
     *
     * EXPLOIT: Create a JWT with "alg":"none" and userId: 999
     * Perform an action - it will be logged with userId: 999 instead of real user
     */
    @Transactional
    public AuditLog logAction(String action, String resource, Long resourceId, String status, String details) {
        Long userId = null;
        Long tenantId = null;

        try {
            // VULNERABILITY: userId comes from JWT which can be forged
            userId = authService.getCurrentUserId();
            tenantId = authService.getCurrentTenantId();
        } catch (Exception e) {
            // If no auth, log anonymously
        }

        HttpServletRequest request = getCurrentRequest();
        String ipAddress = getClientIpAddress(request);
        String userAgent = request != null ? request.getHeader("User-Agent") : null;

        AuditLog log = AuditLog.builder()
                .userId(userId) // VULNERABLE: Can be manipulated via JWT
                .action(action)
                .resource(resource)
                .resourceId(resourceId)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .status(status)
                .details(details)
                .tenantId(tenantId != null ? tenantId : 0L)
                .timestamp(LocalDateTime.now())
                .build();

        return auditLogRepository.save(log);
    }

    public List<AuditLog> getAuditLogs() {
        Long tenantId = authService.getCurrentTenantId();
        return auditLogRepository.findByTenantIdOrderByTimestampDesc(tenantId);
    }

    public List<AuditLog> getUserAuditLogs(Long userId) {
        Long tenantId = authService.getCurrentTenantId();
        return auditLogRepository.findByUserIdAndTenantId(userId, tenantId);
    }

    private HttpServletRequest getCurrentRequest() {
        try {
            ServletRequestAttributes attributes =
                (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
            return attributes.getRequest();
        } catch (Exception e) {
            return null;
        }
    }

    private String getClientIpAddress(HttpServletRequest request) {
        if (request == null) {
            return null;
        }

        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        return request.getRemoteAddr();
    }
}
