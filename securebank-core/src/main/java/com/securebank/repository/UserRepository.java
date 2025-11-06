package com.securebank.repository;

import com.securebank.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);

    Optional<User> findByUsernameAndTenantId(String username, Long tenantId);

    /**
     * VULNERABILITY: Tenant Isolation Failure (CWE-566)
     * This method returns ALL users across all tenants
     * Should filter by tenantId
     */
    List<User> findAll();

    List<User> findByTenantId(Long tenantId);
}
