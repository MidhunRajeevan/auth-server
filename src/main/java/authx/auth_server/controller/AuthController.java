package authx.auth_server.controller;

import authx.auth_server.model.ClientModel;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {
    
    @GetMapping("/")
    public String Welcome()
    {
        return "Login pAge";
    }

    @GetMapping("/notification")
    public String Notification()
    {
        return  "first API";
    }

    @PostMapping("/register-client")
    public ResponseEntity<ClientModel> RegisterClient(ClientModel clientModel){

        ClientModel clientModel1=new ClientModel();

        return new ResponseEntity<ClientModel>(clientModel, HttpStatus.CREATED);
    }
}
