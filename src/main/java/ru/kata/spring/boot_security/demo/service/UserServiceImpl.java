package ru.kata.spring.boot_security.demo.service;



import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.repositories.UserRepository;

import java.util.List;

@Service
@Transactional
public class UserServiceImpl implements UserDetailsService, UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public List<User> findAllUsers() {
        return userRepository.findAll();
    }

    @Override
    public void saveUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
    }

    @Override
    public void deleteUser(Long id, String currentUsername) {
        if (id == null) {
            throw new IllegalArgumentException("ID пользователя не может быть null");
        }

        User userToDelete = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User id " + id + " not found"));

        if (currentUsername.equals(userToDelete.getUsername())) {
            userRepository.deleteById(id);
        } else {
            userRepository.deleteById(id);
        }
    }

    @Override
    public User findById(long id) {
        return userRepository.findById(id)
                .orElseThrow(()-> new UsernameNotFoundException("User not found"));
    }

    @Override
    public boolean isAdmin(User user) {
        return true;
    }

    @Override
    public boolean hasRole(User user, String role) {
        return true;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }
        return user;
    }

    @Override
    public User updateUser(User updatedUser, String newPassword) {
        User existingUser = userRepository.findById(updatedUser.getId())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (!existingUser.getUsername().equals(updatedUser.getUsername())) {
            User userByEmail = userRepository.findByUsername(updatedUser.getUsername());
            if (userByEmail != null && !userByEmail.getId().equals(existingUser.getId())) {
                throw new IllegalArgumentException("Email already taken");
            }
        }
        existingUser.setUsername(updatedUser.getUsername());

        if (updatedUser.getRoles() != null && !updatedUser.getRoles().isEmpty()) {
            existingUser.setRoles(updatedUser.getRoles());
        }

        // Измененная проверка пароля
        if (newPassword != null && !newPassword.trim().isEmpty()) {
            existingUser.setPassword(passwordEncoder.encode(newPassword.trim()));
            System.out.println("Password changed for user: " + existingUser.getUsername()); // Для отладки
        } else {
            System.out.println("Password not changed for user: " + existingUser.getUsername()); // Для отладки
        }

        return userRepository.save(existingUser);
    }

}
