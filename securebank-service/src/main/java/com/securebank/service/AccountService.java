package com.securebank.service;

import com.securebank.domain.Account;
import com.securebank.domain.AccountStatus;
import com.securebank.domain.AccountType;
import com.securebank.repository.AccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.List;
import java.util.Random;

@Service
public class AccountService {

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private AuthService authService;

    /**
     * VULNERABILITY: Weak Random Number Generation (CWE-330)
     * Using java.util.Random for account number generation is predictable
     * Should use SecureRandom instead
     */
    private final Random random = new Random();

    @Transactional
    public Account createAccount(Long userId, AccountType accountType, Long tenantId) {
        String accountNumber = generateAccountNumber();

        Account account = Account.builder()
                .accountNumber(accountNumber)
                .userId(userId)
                .balance(BigDecimal.ZERO)
                .accountType(accountType)
                .status(AccountStatus.ACTIVE)
                .tenantId(tenantId)
                .build();

        return accountRepository.save(account);
    }

    /**
     * VULNERABILITY: Predictable Account Numbers (CWE-330)
     * Using Random instead of SecureRandom makes account numbers predictable
     * An attacker can predict future account numbers and perform attacks
     */
    private String generateAccountNumber() {
        long accountNumber = 1000000000L + (long)(random.nextDouble() * 9000000000L);
        return String.valueOf(accountNumber);
    }

    public Account getAccountById(Long id) {
        return accountRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Account not found with id: " + id));
    }

    public List<Account> getUserAccounts(Long userId) {
        return accountRepository.findByUserId(userId);
    }

    public List<Account> getCurrentUserAccounts() {
        Long userId = authService.getCurrentUserId();
        Long tenantId = authService.getCurrentTenantId();
        return accountRepository.findByUserIdAndTenantId(userId, tenantId);
    }

    /**
     * VULNERABILITY: Tenant Isolation Failure (CWE-566)
     * This method calls findAll() which returns accounts across all tenants
     */
    public List<Account> getAllAccounts() {
        return accountRepository.findAll();
    }

    @Transactional
    public Account updateBalance(Long accountId, BigDecimal newBalance) {
        Account account = getAccountById(accountId);
        account.setBalance(newBalance);
        return accountRepository.save(account);
    }
}
