package com.securebank.auth;

import com.securebank.domain.ApiKey;
import com.securebank.repository.ApiKeyRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Optional;

@Component
public class ApiKeyAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private ApiKeyRepository apiKeyRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            String apiKey = getApiKeyFromRequest(request);

            if (StringUtils.hasText(apiKey)) {
                // VULNERABILITY: Storing API keys in plain text (CWE-522)
                // Should be hashed like passwords
                Optional<ApiKey> apiKeyEntity = apiKeyRepository.findByKeyHashAndIsActiveTrue(apiKey);

                if (apiKeyEntity.isPresent()) {
                    ApiKey key = apiKeyEntity.get();

                    // Update last used timestamp
                    key.setLastUsedAt(LocalDateTime.now());
                    apiKeyRepository.save(key);

                    // Create authentication
                    UserPrincipal principal = new UserPrincipal(
                            key.getUserId(),
                            "api-key-user",
                            null,
                            null,
                            "API_USER",
                            key.getTenantId(),
                            Collections.singleton(new SimpleGrantedAuthority("ROLE_API_USER"))
                    );

                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        } catch (Exception ex) {
            logger.error("Could not set API key authentication in security context", ex);
        }

        filterChain.doFilter(request, response);
    }

    private String getApiKeyFromRequest(HttpServletRequest request) {
        String apiKey = request.getHeader("X-API-Key");
        if (!StringUtils.hasText(apiKey)) {
            apiKey = request.getParameter("api_key");
        }
        return apiKey;
    }
}
