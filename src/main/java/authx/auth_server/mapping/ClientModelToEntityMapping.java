package authx.auth_server.mapping;


import authx.auth_server.entity.ClientEntity;
import authx.auth_server.model.ClientModel;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.sql.Timestamp;
import org.springframework.stereotype.Component;

@Component
public class ClientModelToEntityMapping {

    public ClientEntity ModelToEntityMapping(ClientModel modelClient) {

        ClientEntity clientEntity = new ClientEntity();
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        clientEntity.setClientId(modelClient.getClientId());
        clientEntity.setClientSecret(modelClient.getClientSecret());
        clientEntity.setAuthorizedGrantTypes(modelClient.getAuthorizedGrantTypes());
        clientEntity.setAccessTokenValidity(modelClient.getAccessTokenValidity());
        clientEntity.setRefreshTokenValidity(modelClient.getRefreshTokenValidity());
        clientEntity.setStatus(modelClient.getStatus());
        clientEntity.setCreatedBy(modelClient.getCreatedBy());
        clientEntity.setUpdatedBy(modelClient.getUpdatedBy());
        clientEntity.setCreatedAt(timestamp);
        clientEntity.setUpdatedAt(timestamp);
        ObjectMapper objectMapper = new ObjectMapper();
        if (modelClient.getAuthorities() != null) {
            try {
                clientEntity.setAuthorities(objectMapper.writeValueAsString(modelClient.getAuthorities()));
            } catch (Exception e) {
                throw new RuntimeException("Error converting applications to JSON", e);
            }
        }

        if (modelClient.getAdditionalInformation() != null) {
            try {
                clientEntity.setAdditionalInformation(objectMapper.writeValueAsString(modelClient.getAdditionalInformation()));
            } catch (Exception e) {
                throw new RuntimeException("Error converting additional information to JSON", e);
            }
        }
        
        return clientEntity;
    }
}
