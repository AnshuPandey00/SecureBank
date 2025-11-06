package com.securebank.service;

import com.securebank.domain.ApiKey;
import com.securebank.repository.ApiKeyRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Random;

/**
 * VULNERABILITY: Cryptographic Failure (CWE-327)
 * Using java.util.Random for API key generation
 * Predictable random number generation allows attackers to guess API keys
 */
@Service
public class ApiKeyService {

    @Autowired
    private ApiKeyRepository apiKeyRepository;

    @Autowired
    private AuthService authService;

    /**
     * VULNERABILITY: Weak Random Number Generator (CWE-330, CWE-327)
     * java.util.Random is NOT cryptographically secure
     * Attackers can predict the sequence and generate valid API keys
     */
    private final Random random = new Random();

    /**
     * VULNERABILITY: Predictable API Key Generation (CWE-327)
     * API keys are generated using predictable Random
     * Should use SecureRandom or UUID
     *
     * EXPLOIT: Monitor a few generated API keys to determine the Random seed
     * Then predict future API keys
     */
    @Transactional
    public ApiKey generateApiKey(Long userId, String permissions) {
        String apiKey = generateKey();

        ApiKey key = ApiKey.builder()
                .userId(userId)
                .keyHash(apiKey) // VULNERABILITY: Also storing in plain text instead of hashing
                .permissionsJson(permissions)
                .isActive(true)
                .tenantId(authService.getCurrentTenantId())
                .build();

        return apiKeyRepository.save(key);
    }

    /**
     * VULNERABILITY: Weak key generation (CWE-327)
     * Using Random.nextLong() which is predictable
     */
    private String generateKey() {
        // VULNERABLE: Using Random instead of SecureRandom!
        long randomValue = random.nextLong();
        return "sk_" + Long.toHexString(Math.abs(randomValue));
    }

    public List<ApiKey> getUserApiKeys(Long userId) {
        return apiKeyRepository.findByUserId(userId);
    }

    public List<ApiKey> getCurrentUserApiKeys() {
        Long userId = authService.getCurrentUserId();
        Long tenantId = authService.getCurrentTenantId();
        return apiKeyRepository.findByUserIdAndTenantId(userId, tenantId);
    }

    @Transactional
    public void revokeApiKey(Long keyId) {
        ApiKey key = apiKeyRepository.findById(keyId)
                .orElseThrow(() -> new RuntimeException("API key not found"));
        key.setIsActive(false);
        apiKeyRepository.save(key);
    }
}
