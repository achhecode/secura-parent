package com.achhecode.securaweb.controller;

import com.achhecode.securacore.core.MessageCrypto;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/message")
public class MessageController {

    private final MessageCrypto messageCrypto;

    public MessageController(MessageCrypto messageCrypto) {
        this.messageCrypto = messageCrypto;
    }

    @PostMapping("/encrypt")
    public String encrypt(
            @RequestParam("text") String text,
            @RequestParam("password") String password,
            Model model) {

        try {
            String encrypted = messageCrypto.encrypt(text, password.toCharArray());

            model.addAttribute("result", encrypted);
            model.addAttribute("success", "Message encrypted successfully.");

        } catch (Exception e) {
            model.addAttribute("error",
                    "Encryption failed: " + e.getMessage());
        }

        return "index";
    }

    @PostMapping("/decrypt")
    public String decrypt(
            @RequestParam("text") String text,
            @RequestParam("password") String password,
            Model model) {

        try {
            String decrypted = messageCrypto.decrypt(text, password.toCharArray());

            model.addAttribute("result", decrypted);
            model.addAttribute("success", "Message decrypted successfully.");

        } catch (Exception e) {
            model.addAttribute("error",
                    "Decryption failed: " + e.getMessage());
        }

        return "index";
    }
}
