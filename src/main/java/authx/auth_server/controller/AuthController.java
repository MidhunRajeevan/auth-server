package authx.auth_server.controller;

import authx.auth_server.model.ClientModel;
import authx.auth_server.service.ClientService;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    private static final Logger log = LogManager.getLogger(AuthController.class);

    @Autowired
    private ClientService clientService;
    
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
    public ResponseEntity<ClientModel> RegisterClient(@RequestBody ClientModel clientModel){

        log.debug(clientModel);
        clientService.RegisterClient(clientModel);

        return new ResponseEntity<ClientModel>(clientModel, HttpStatus.CREATED);
    }

}
