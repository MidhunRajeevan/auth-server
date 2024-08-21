package authx.auth_server.mapping;


import authx.auth_server.entity.ClientEntity;
import authx.auth_server.model.Application;
import authx.auth_server.model.ClientModel;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;

public class ClientModelToEntityMapping {

    public ClientEntity ModelToEntityMapping(ClientModel modelClient) {

        ClientEntity clientEntity = new ClientEntity();

        // Basic fields
        clientEntity.setClientId(modelClient.getClientId());
        clientEntity.setClientSecret(modelClient.getClientSecret());
        clientEntity.setAuthorizedGrantTypes(modelClient.getAuthorizedGrantTypes());
        clientEntity.setAuthorities(modelClient.getAuthorities());
        clientEntity.setAccessTokenValidity(modelClient.getAccessTokenValidity());
        clientEntity.setRefreshTokenValidity(modelClient.getRefreshTokenValidity());
//        clientEntity.setAdditionalInformation(modelClient.getAdditionalInformation());
        clientEntity.setStatus(modelClient.getStatus());
        clientEntity.setCreatedBy(modelClient.getCreatedBy());
        clientEntity.setUpdatedBy(modelClient.getUpdatedBy());
        clientEntity.setCreatedAt(modelClient.getCreatedAt());
        clientEntity.setUpdatedAt(modelClient.getUpdatedAt());
        ObjectMapper objectMapper = new ObjectMapper();
        List<Application> applications=modelClient.getApplications();

        return clientEntity;
    }
}
