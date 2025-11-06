package com.securebank.controller;

import com.securebank.domain.UserSession;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Base64;

/**
 * VULNERABILITY: Insecure Deserialization (CWE-502)
 * This controller deserializes user-controlled data without validation
 * Can lead to Remote Code Execution (RCE)
 */
@RestController
@RequestMapping("/api/session")
public class SessionController {

    /**
     * VULNERABILITY: Insecure Deserialization (CWE-502)
     * Deserializes base64-encoded Java objects from user input
     * This is EXTREMELY dangerous and can lead to RCE
     *
     * EXPLOIT: Create a malicious serialized object (e.g., using ysoserial)
     * that executes code when deserialized. Encode it as base64 and send it.
     *
     * Example attack flow:
     * 1. Attacker creates a gadget chain using ysoserial
     * 2. Serializes a malicious object that executes system commands
     * 3. Base64 encodes it
     * 4. Sends POST /api/session/restore with sessionData=<malicious_payload>
     * 5. Server deserializes it, triggering code execution
     */
    @PostMapping("/restore")
    public ResponseEntity<?> restoreSession(@RequestParam String sessionData) {
        try {
            // VULNERABLE: Deserializing untrusted data!
            byte[] bytes = Base64.getDecoder().decode(sessionData);
            ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
            ObjectInputStream ois = new ObjectInputStream(bais);

            // This is where the vulnerability is exploited
            // Any malicious code in the serialized object will execute here
            UserSession session = (UserSession) ois.readObject();
            ois.close();

            return ResponseEntity.ok(session);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to restore session: " + e.getMessage());
        }
    }

    @GetMapping("/test")
    public ResponseEntity<?> testEndpoint() {
        return ResponseEntity.ok("Session controller is working");
    }
}
