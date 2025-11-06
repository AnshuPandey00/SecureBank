package com.securebank.repository;

import com.securebank.domain.ApiKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ApiKeyRepository extends JpaRepository<ApiKey, Long> {

    Optional<ApiKey> findByKeyHash(String keyHash);

    List<ApiKey> findByUserId(Long userId);

    List<ApiKey> findByUserIdAndTenantId(Long userId, Long tenantId);

    Optional<ApiKey> findByKeyHashAndIsActiveTrue(String keyHash);
}
