package authx.auth_server.service;

import authx.auth_server.entity.ClientEntity;
import authx.auth_server.mapping.ClientModelToEntityMapping;
import authx.auth_server.model.ClientModel;
import authx.auth_server.repository.ClientRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class ClientService {

    @Autowired
    private ClientRepository clientRepository;

    @Autowired
    private ClientModelToEntityMapping clientModelToEntityMapping;

    public ClientModel RegisterClient(ClientModel clientModel){
        ClientModel clientModel1= new ClientModel();
        ClientEntity clientEntity= clientModelToEntityMapping.ModelToEntityMapping(clientModel);
        ClientEntity savedEntity=clientRepository.saveAndFlush(clientEntity);

        return  clientModel;
    }
}
