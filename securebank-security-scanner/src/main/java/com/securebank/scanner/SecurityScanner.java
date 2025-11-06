package com.securebank.scanner;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.BlockStmt;
import lombok.Data;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Custom Static Security Analyzer for SecureBank
 * Detects the 12 intentional security vulnerabilities in the codebase
 */
public class SecurityScanner {

    private final List<SecurityFinding> findings = new ArrayList<>();
    private final JavaParser javaParser = new JavaParser();

    public static void main(String[] args) {
        String projectPath = args.length > 0 ? args[0] : ".";
        SecurityScanner scanner = new SecurityScanner();

        System.out.println("==========================================================");
        System.out.println("  SecureBank Security Scanner");
        System.out.println("  Scanning for intentional security vulnerabilities...");
        System.out.println("==========================================================\n");

        scanner.scanProject(projectPath);
        scanner.printFindings();
    }

    public void scanProject(String projectPath) {
        try (Stream<Path> paths = Files.walk(Paths.get(projectPath))) {
            paths.filter(Files::isRegularFile)
                    .filter(p -> p.toString().endsWith(".java"))
                    .forEach(this::scanFile);
        } catch (IOException e) {
            System.err.println("Error scanning project: " + e.getMessage());
        }
    }

    private void scanFile(Path filePath) {
        try {
            CompilationUnit cu = javaParser.parse(filePath).getResult().orElse(null);
            if (cu == null) return;

            String fileName = filePath.toString();

            // Scan for different vulnerability types
            scanForSQLInjection(cu, fileName);
            scanForMissingAuthorization(cu, fileName);
            scanForMissingLocking(cu, fileName);
            scanForJWTAlgorithmConfusion(cu, fileName);
            scanForMassAssignment(cu, fileName);
            scanForInsecureDeserialization(cu, fileName);
            scanForWeakRandom(cu, fileName);
            scanForCSRFDisabled(cu, fileName);
            scanForTenantIsolationFailure(cu, fileName);

        } catch (IOException e) {
            System.err.println("Error parsing file " + filePath + ": " + e.getMessage());
        }
    }

    /**
     * CWE-89: SQL Injection Detection
     * Looks for string concatenation in native SQL queries
     */
    private void scanForSQLInjection(CompilationUnit cu, String fileName) {
        cu.findAll(VariableDeclarationExpr.class).forEach(var -> {
            var.getVariables().forEach(v -> {
                if (v.getInitializer().isPresent()) {
                    Expression init = v.getInitializer().get();
                    if (init instanceof BinaryExpr) {
                        BinaryExpr binExpr = (BinaryExpr) init;
                        String exprStr = binExpr.toString();

                        // Check for SQL query construction with concatenation
                        if (exprStr.contains("SELECT") && exprStr.contains("+")) {
                            findings.add(new SecurityFinding(
                                    "SQL Injection (CWE-89)",
                                    fileName,
                                    v.getBegin().isPresent() ? v.getBegin().get().line : 0,
                                    "HIGH",
                                    exprStr,
                                    "SQL query built using string concatenation with user input. " +
                                            "Use parameterized queries or JPA methods instead."
                            ));
                        }
                    }
                }
            });
        });
    }

    /**
     * CWE-639: Missing Authorization Checks
     * Looks for controller methods that access resources without authorization
     */
    private void scanForMissingAuthorization(CompilationUnit cu, String fileName) {
        if (!fileName.contains("Controller")) return;

        cu.findAll(MethodDeclaration.class).forEach(method -> {
            // Check if method has @GetMapping or @PostMapping with path variable
            boolean hasPathVariable = method.getParameters().stream()
                    .anyMatch(p -> p.getAnnotations().stream()
                            .anyMatch(a -> a.getNameAsString().equals("PathVariable")));

            if (hasPathVariable && method.getBody().isPresent()) {
                BlockStmt body = method.getBody().get();
                String bodyStr = body.toString();

                // Look for direct repository/service calls without authorization check
                boolean hasAuthCheck = bodyStr.contains("getCurrentUser") ||
                        bodyStr.contains("checkOwnership") ||
                        bodyStr.contains("verifyAccess") ||
                        bodyStr.contains("@PreAuthorize");

                if (!hasAuthCheck && (bodyStr.contains("findById") || bodyStr.contains("getById"))) {
                    findings.add(new SecurityFinding(
                            "Insecure Direct Object Reference - IDOR (CWE-639)",
                            fileName,
                            method.getBegin().isPresent() ? method.getBegin().get().line : 0,
                            "HIGH",
                            method.getNameAsString() + "()",
                            "Method accepts ID parameter but doesn't verify user authorization. " +
                                    "Add ownership check before returning resource."
                    ));
                }
            }
        });
    }

    /**
     * CWE-362: Missing Transaction Locking
     * Looks for @Transactional without pessimistic locking on financial operations
     */
    private void scanForMissingLocking(CompilationUnit cu, String fileName) {
        cu.findAll(MethodDeclaration.class).forEach(method -> {
            String methodName = method.getNameAsString().toLowerCase();

            // Check financial operations
            if ((methodName.contains("transfer") || methodName.contains("withdraw"))
                    && method.getBody().isPresent()) {

                BlockStmt body = method.getBody().get();
                String bodyStr = body.toString();

                // Check for balance check without locking
                boolean hasBalanceCheck = bodyStr.contains("getBalance") || bodyStr.contains("balance");
                boolean hasLocking = bodyStr.contains("Lock") || bodyStr.contains("findByIdWithLock");

                if (hasBalanceCheck && !hasLocking) {
                    findings.add(new SecurityFinding(
                            "Race Condition in Transfer (CWE-362)",
                            fileName,
                            method.getBegin().isPresent() ? method.getBegin().get().line : 0,
                            "HIGH",
                            method.getNameAsString() + "()",
                            "Financial transaction without pessimistic locking. " +
                                    "Use @Lock(LockModeType.PESSIMISTIC_WRITE) on repository method."
                    ));
                }
            }
        });
    }

    /**
     * CWE-347: JWT Algorithm Confusion
     * Looks for JWT validation without algorithm verification
     */
    private void scanForJWTAlgorithmConfusion(CompilationUnit cu, String fileName) {
        cu.findAll(MethodDeclaration.class).forEach(method -> {
            if (method.getNameAsString().contains("validate") && method.getBody().isPresent()) {
                String bodyStr = method.getBody().get().toString();

                if (bodyStr.contains("parseClaimsJws") &&
                        !bodyStr.contains("requireAlgorithm") &&
                        !bodyStr.contains("setSigningKeyResolver")) {

                    findings.add(new SecurityFinding(
                            "JWT Algorithm Confusion (CWE-347)",
                            fileName,
                            method.getBegin().isPresent() ? method.getBegin().get().line : 0,
                            "CRITICAL",
                            method.getNameAsString() + "()",
                            "JWT validation doesn't verify the algorithm. " +
                                    "Add .requireAlgorithm() to reject 'none' algorithm tokens."
                    ));
                }
            }
        });
    }

    /**
     * CWE-915: Mass Assignment
     * Looks for @RequestBody with entity classes
     */
    private void scanForMassAssignment(CompilationUnit cu, String fileName) {
        if (!fileName.contains("Controller")) return;

        cu.findAll(MethodDeclaration.class).forEach(method -> {
            method.getParameters().forEach(param -> {
                boolean hasRequestBody = param.getAnnotations().stream()
                        .anyMatch(a -> a.getNameAsString().equals("RequestBody"));

                if (hasRequestBody) {
                    String paramType = param.getTypeAsString();

                    // Check if binding directly to entity (not DTO)
                    if (paramType.equals("Loan") || paramType.equals("User") ||
                            paramType.equals("Account") || paramType.equals("Transaction")) {

                        findings.add(new SecurityFinding(
                                "Mass Assignment (CWE-915)",
                                fileName,
                                param.getBegin().isPresent() ? param.getBegin().get().line : 0,
                                "HIGH",
                                method.getNameAsString() + "(@RequestBody " + paramType + ")",
                                "Controller accepts entity class directly. " +
                                        "Use DTO to prevent mass assignment of restricted fields."
                        ));
                    }
                }
            });
        });
    }

    /**
     * CWE-502: Insecure Deserialization
     * Looks for ObjectInputStream usage
     */
    private void scanForInsecureDeserialization(CompilationUnit cu, String fileName) {
        cu.findAll(ObjectCreationExpr.class).forEach(expr -> {
            if (expr.getTypeAsString().equals("ObjectInputStream")) {
                findings.add(new SecurityFinding(
                        "Insecure Deserialization (CWE-502)",
                        fileName,
                        expr.getBegin().isPresent() ? expr.getBegin().get().line : 0,
                        "CRITICAL",
                        expr.toString(),
                        "Deserializing untrusted data using ObjectInputStream. " +
                                "This can lead to Remote Code Execution. Use JSON instead."
                ));
            }
        });
    }

    /**
     * CWE-330: Weak Random Number Generation
     * Looks for Random instead of SecureRandom in security contexts
     */
    private void scanForWeakRandom(CompilationUnit cu, String fileName) {
        cu.findAll(ObjectCreationExpr.class).forEach(expr -> {
            if (expr.getTypeAsString().equals("Random") &&
                    (fileName.contains("ApiKey") || fileName.contains("Account") ||
                            fileName.contains("Token") || fileName.contains("Key"))) {

                findings.add(new SecurityFinding(
                        "Weak Random Number Generation (CWE-330)",
                        fileName,
                        expr.getBegin().isPresent() ? expr.getBegin().get().line : 0,
                        "MEDIUM",
                        "new Random()",
                        "Using java.util.Random for security-sensitive operation. " +
                                "Use SecureRandom instead for cryptographic operations."
                ));
            }
        });
    }

    /**
     * CWE-352: CSRF Protection Disabled
     * Looks for csrf().disable() in security config
     */
    private void scanForCSRFDisabled(CompilationUnit cu, String fileName) {
        if (!fileName.contains("SecurityConfig")) return;

        cu.findAll(MethodCallExpr.class).forEach(call -> {
            if (call.getNameAsString().equals("disable") &&
                    call.getScope().isPresent() &&
                    call.getScope().get().toString().contains("csrf")) {

                findings.add(new SecurityFinding(
                        "CSRF Protection Disabled (CWE-352)",
                        fileName,
                        call.getBegin().isPresent() ? call.getBegin().get().line : 0,
                        "HIGH",
                        call.toString(),
                        "CSRF protection is disabled. " +
                                "Enable CSRF for state-changing operations or use custom tokens."
                ));
            }
        });
    }

    /**
     * CWE-566: Tenant Isolation Failure
     * Looks for findAll() without tenant filtering
     */
    private void scanForTenantIsolationFailure(CompilationUnit cu, String fileName) {
        if (!fileName.contains("Service") && !fileName.contains("Controller")) return;

        cu.findAll(MethodCallExpr.class).forEach(call -> {
            if (call.getNameAsString().equals("findAll") &&
                    (fileName.contains("Account") || fileName.contains("Transaction") ||
                            fileName.contains("User") || fileName.contains("Loan"))) {

                findings.add(new SecurityFinding(
                        "Tenant Isolation Failure (CWE-566)",
                        fileName,
                        call.getBegin().isPresent() ? call.getBegin().get().line : 0,
                        "HIGH",
                        call.toString(),
                        "Using findAll() without tenant filtering. " +
                                "Add tenantId filter to prevent cross-tenant data access."
                ));
            }
        });
    }

    private void printFindings() {
        System.out.println("\n==========================================================");
        System.out.println("  SCAN RESULTS");
        System.out.println("==========================================================\n");

        if (findings.isEmpty()) {
            System.out.println("No vulnerabilities found.");
            return;
        }

        // Group by severity
        long critical = findings.stream().filter(f -> f.severity.equals("CRITICAL")).count();
        long high = findings.stream().filter(f -> f.severity.equals("HIGH")).count();
        long medium = findings.stream().filter(f -> f.severity.equals("MEDIUM")).count();

        System.out.println("Total Findings: " + findings.size());
        System.out.println("  CRITICAL: " + critical);
        System.out.println("  HIGH: " + high);
        System.out.println("  MEDIUM: " + medium);
        System.out.println();

        // Print each finding
        int count = 1;
        for (SecurityFinding finding : findings) {
            System.out.println("[" + count++ + "] " + finding.vulnerability);
            System.out.println("    Severity: " + finding.severity);
            System.out.println("    File: " + finding.file);
            System.out.println("    Line: " + finding.line);
            System.out.println("    Code: " + finding.codeSnippet);
            System.out.println("    Fix: " + finding.remediation);
            System.out.println();
        }
    }

    @Data
    private static class SecurityFinding {
        private final String vulnerability;
        private final String file;
        private final int line;
        private final String severity;
        private final String codeSnippet;
        private final String remediation;
    }
}
