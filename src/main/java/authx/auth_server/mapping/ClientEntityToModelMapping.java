package authx.auth_server.mapping;

import authx.auth_server.entity.ClientEntity;
import authx.auth_server.model.ClientModel;
import authx.auth_server.model.Authorities;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.sql.Timestamp;
import java.util.List;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import org.springframework.stereotype.Component;

@Component
public class ClientEntityToModelMapping {

      public ClientModel EntityToModelMapping(ClientEntity clientEntity) throws JsonMappingException, JsonProcessingException {
        
        ClientModel clientModel = new ClientModel();
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        clientModel.setClientId(clientEntity.getClientId());
        clientModel.setClientSecret(clientEntity.getClientSecret());
        clientModel.setAuthorizedGrantTypes(clientEntity.getAuthorizedGrantTypes());
        clientModel.setAccessTokenValidity(clientEntity.getAccessTokenValidity());
        clientModel.setRefreshTokenValidity(clientEntity.getRefreshTokenValidity());
        clientModel.setStatus(clientEntity.getStatus());
        clientModel.setCreatedBy(clientEntity.getCreatedBy());
        clientModel.setUpdatedBy(clientEntity.getUpdatedBy());
        clientModel.setCreatedAt(timestamp);
        clientModel.setUpdatedAt(timestamp);
        ObjectMapper objectMapper = new ObjectMapper();
		    List<Authorities> addressInfoList = objectMapper.readValue(clientEntity.getAuthorities(), new TypeReference<List<Authorities>>() {});
        clientModel.setAuthorities(addressInfoList);
        return clientModel;
      }


}
