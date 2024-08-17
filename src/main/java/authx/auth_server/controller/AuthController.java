package authx.auth_server.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {
    
    @GetMapping("/")
    public String Welcome()
    {
        return "Welcome";
    }
}
