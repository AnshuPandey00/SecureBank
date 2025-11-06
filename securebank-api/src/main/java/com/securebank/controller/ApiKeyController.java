package com.securebank.controller;

import com.securebank.domain.ApiKey;
import com.securebank.service.ApiKeyService;
import com.securebank.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/api-keys")
public class ApiKeyController {

    @Autowired
    private ApiKeyService apiKeyService;

    @Autowired
    private AuthService authService;

    /**
     * VULNERABILITY: Weak cryptographic key generation (CWE-327)
     * The service uses Random instead of SecureRandom
     */
    @PostMapping("/generate")
    public ResponseEntity<?> generateApiKey(@RequestBody GenerateKeyRequest request) {
        try {
            Long userId = authService.getCurrentUserId();
            ApiKey apiKey = apiKeyService.generateApiKey(userId, request.getPermissions());
            return ResponseEntity.ok(apiKey);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to generate API key: " + e.getMessage());
        }
    }

    @GetMapping("/my-keys")
    public ResponseEntity<?> getMyApiKeys() {
        List<ApiKey> apiKeys = apiKeyService.getCurrentUserApiKeys();
        return ResponseEntity.ok(apiKeys);
    }

    @DeleteMapping("/{keyId}")
    public ResponseEntity<?> revokeApiKey(@PathVariable Long keyId) {
        try {
            apiKeyService.revokeApiKey(keyId);
            return ResponseEntity.ok("API key revoked successfully");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to revoke API key: " + e.getMessage());
        }
    }

    // DTO
    public static class GenerateKeyRequest {
        private String permissions;

        public String getPermissions() { return permissions; }
        public void setPermissions(String permissions) { this.permissions = permissions; }
    }
}
