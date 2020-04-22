package com.example.security.auth;

import org.assertj.core.util.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.security.secutrity.UserRole.*;

@Repository("fake")
public class ApplicationUserDaoService implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers().stream()
                .filter(applicationUser ->
                        username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers(){
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser("dev",
                        passwordEncoder.encode("dev"),
                        STUDENT.grantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                        ),
                new ApplicationUser("admin",
                        passwordEncoder.encode("dev"),
                        ADMIN.grantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser("trainee",
                        passwordEncoder.encode("dev"),
                        ADMIN_TRAINEE.grantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                )
        );
        return applicationUsers;
    }
}
