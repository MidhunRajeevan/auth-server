package authx.auth_server.mapping;


import authx.auth_server.entity.UserEntity;
import authx.auth_server.model.UserModel;

import java.sql.Timestamp;
import org.springframework.stereotype.Component;

@Component
public class ClientModelToEntityMapping {

    public UserEntity ModelToEntityMapping(UserModel modelClient) {

        UserEntity clientEntity = new UserEntity();
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        clientEntity.setUsername(modelClient.getUsername());
        clientEntity.setPassword(modelClient.getPassword());
        clientEntity.setStatus(modelClient.getStatus());
        clientEntity.setCreatedBy(modelClient.getCreatedBy());
        clientEntity.setUpdatedBy(modelClient.getUpdatedBy());
        clientEntity.setCreatedAt(timestamp);
        clientEntity.setUpdatedAt(timestamp);
        clientEntity.setRole(modelClient.getRole());
        return clientEntity;
    }
}
