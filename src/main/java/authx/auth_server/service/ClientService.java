package authx.auth_server.service;

import authx.auth_server.entity.ClientEntity;
import authx.auth_server.mapping.ClientModelToEntityMapping;
import authx.auth_server.model.ClientModel;
import authx.auth_server.repository.ClientRepository;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ClientService {

    @Autowired
    private ClientRepository clientRepository;

    @Autowired
    private final PasswordEncoder passwordEncoder;

    @Autowired
    private ClientModelToEntityMapping clientModelToEntityMapping;

    public ClientModel RegisterClient(ClientModel clientModel){

        clientModel.setClientSecret(passwordEncoder.encode(clientModel.getClientSecret()));
        ClientEntity clientEntity= clientModelToEntityMapping.ModelToEntityMapping(clientModel);
        clientRepository.saveAndFlush(clientEntity);

        return  clientModel;
    }
}
