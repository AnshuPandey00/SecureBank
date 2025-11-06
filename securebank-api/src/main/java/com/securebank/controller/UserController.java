package com.securebank.controller;

import com.securebank.domain.User;
import com.securebank.repository.UserRepository;
import com.securebank.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * VULNERABILITY: Horizontal Privilege Escalation (CWE-639)
 * Users can update other users' information by changing the userId in the path
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuthService authService;

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser() {
        Long userId = authService.getCurrentUserId();
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return ResponseEntity.ok(user);
    }

    /**
     * VULNERABILITY: Horizontal Privilege Escalation (CWE-639)
     * No check to verify userId matches the authenticated user
     * User A can update User B's email by sending PUT /api/users/B_ID
     *
     * EXPLOIT: User with ID 5 sends: PUT /api/users/10
     * Body: {"email": "hacked@example.com"}
     * This will update user 10's email!
     */
    @PutMapping("/{userId}")
    public ResponseEntity<?> updateUser(@PathVariable Long userId, @RequestBody UserUpdateRequest request) {
        try {
            // VULNERABLE: No check if userId matches authenticated user!
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            if (request.getEmail() != null) {
                user.setEmail(request.getEmail());
            }

            userRepository.save(user);
            return ResponseEntity.ok(user);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Update failed: " + e.getMessage());
        }
    }

    /**
     * VULNERABILITY: Information Disclosure
     * Any authenticated user can view any other user's details
     */
    @GetMapping("/{userId}")
    public ResponseEntity<?> getUser(@PathVariable Long userId) {
        try {
            // VULNERABLE: No authorization check
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));
            return ResponseEntity.ok(user);
        } catch (Exception e) {
            return ResponseEntity.notFound().build();
        }
    }

    // DTO
    public static class UserUpdateRequest {
        private String email;

        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
    }
}
