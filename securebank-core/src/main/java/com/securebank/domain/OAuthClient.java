package com.securebank.domain;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "oauth_clients")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OAuthClient {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_id", nullable = false, unique = true)
    private String clientId;

    @Column(name = "client_secret", nullable = false)
    private String clientSecret;

    @Column(name = "redirect_uris", columnDefinition = "TEXT")
    private String redirectUris;

    @Column(name = "grant_types", nullable = false, length = 500)
    private String grantTypes;

    @Column(length = 500)
    private String scopes;

    @Column(name = "tenant_id", nullable = false)
    private Long tenantId;

    @Column(name = "is_active")
    private Boolean isActive = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        if (isActive == null) {
            isActive = true;
        }
    }
}
