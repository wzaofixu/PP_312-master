package ru.kata.spring.boot_security.demo.controller;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.service.RoleService;
import ru.kata.spring.boot_security.demo.service.RoleServiceImpl;
import ru.kata.spring.boot_security.demo.service.UserService;
import ru.kata.spring.boot_security.demo.service.UserServiceImpl;

import java.security.Principal;

@Controller
@RequestMapping("/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final UserService userService;
    private final RoleService roleService;

    @Autowired
    public AdminController(UserService userService, RoleService roleService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.roleService = roleService;
    }

    @GetMapping
    public String showAllUsers(Model model) {
        model.addAttribute("allUsers", userService.findAllUsers());
        return "admin";
    }

    @GetMapping("/new")
    public String showNewUserForm(Model model) {
        model.addAttribute("user", new User());
        model.addAttribute("allRoles", roleService.getAllRoles());
        return "admin";
    }

    @PostMapping("/save")
    public String saveUser(@ModelAttribute("user") User user) {
        userService.saveUser(user);
        return "redirect:/admin";
    }

    @PostMapping("delete_user")
    public String deleteUser(@RequestParam("id") Long id, Principal principal) {
        userService.deleteUser(id, principal.getName());
        return principal.getName().equals(userService.findById(id).getUsername())
                ? "redirect:/login?logout"
                : "redirect:/admin";
    }

    @GetMapping("/edit/{id}")
    public String showUpdateUserForm(@PathVariable("id") Long id, Model model, Principal principal) {
        User userToEdit = userService.findById(id);
        User authUser = userService.findByUsername(principal.getName());

        model.addAttribute("user", userToEdit);
        model.addAttribute("authUser", authUser);
        model.addAttribute("allRoles", roleService.getAllRoles());
        return "admin";
    }

    @PostMapping("/update")
    public String updateUser(@ModelAttribute("user") User updatedUser,
                             @RequestParam(value = "newPassword", required = false) String newPassword) {
        userService.updateUser(updatedUser, newPassword);
        return "redirect:/admin";
    }

}
