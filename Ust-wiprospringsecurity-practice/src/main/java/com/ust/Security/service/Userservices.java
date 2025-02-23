package com.ust.Security.service;

import com.ust.Security.dto.ForgotPasswordRequest;
import com.ust.Security.dto.ResetPasswordRequest;
import com.ust.Security.model.PasswordResetToken;
import com.ust.Security.model.Userinfo;
import com.ust.Security.repository.PasswordResetTokenRepository;
import com.ust.Security.repository.Userinforepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
public class Userservices {

    @Autowired
    private Userinforepository repository;

    @Autowired
    private PasswordResetTokenRepository tokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public String addUser(Userinfo userInfo) {
        userInfo.setPassword(passwordEncoder.encode(userInfo.getPassword()));
        repository.save(userInfo);
        return "User added to system";
    }

    // Generate password reset token and return it in the response
    public String initiatePasswordReset(ForgotPasswordRequest request) {
        Optional<Userinfo> userOptional = repository.findByEmail(request.getEmail());

        if (userOptional.isPresent()) {
            Userinfo user = userOptional.get();

            // Generate a unique reset token
            String token = UUID.randomUUID().toString();

            PasswordResetToken resetToken = new PasswordResetToken();
            resetToken.setToken(token);
            resetToken.setUser(user);
            resetToken.setExpiryDate(LocalDateTime.now().plusHours(1)); // Token valid for 1 hour
            tokenRepository.save(resetToken);

            // Return token directly in response (for Swagger copy-paste)
            return "Your password reset token: " + token;
        }

        return "Email not found.";
    }

    // Validate token and reset password
    public String resetPassword(ResetPasswordRequest request) {
        Optional<PasswordResetToken> tokenOptional = tokenRepository.findByToken(request.getToken());

        if (tokenOptional.isPresent()) {
            PasswordResetToken resetToken = tokenOptional.get();

            if (resetToken.getExpiryDate().isAfter(LocalDateTime.now())) {
                Userinfo user = resetToken.getUser();
                user.setPassword(passwordEncoder.encode(request.getNewPassword()));
                repository.save(user);

                // Delete token after successful reset
                tokenRepository.delete(resetToken);

                return "Password reset successful.";
            }

            return "Token has expired.";
        }

        return "Invalid token.";
    }
}
