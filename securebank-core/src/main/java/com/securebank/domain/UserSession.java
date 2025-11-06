package com.securebank.domain;

import lombok.*;
import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * VULNERABILITY: Insecure Deserialization (CWE-502)
 * This class is Serializable and will be deserialized from user input
 * Can be exploited for remote code execution
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserSession implements Serializable {
    private static final long serialVersionUID = 1L;

    private Long userId;
    private String username;
    private String sessionId;
    private LocalDateTime loginTime;
    private String ipAddress;
}
