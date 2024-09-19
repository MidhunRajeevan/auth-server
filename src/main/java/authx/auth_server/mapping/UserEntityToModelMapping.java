package authx.auth_server.mapping;

import authx.auth_server.entity.UserEntity;
import authx.auth_server.model.UserModel;

import com.fasterxml.jackson.databind.JsonMappingException;

import java.sql.Timestamp;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.springframework.stereotype.Component;

@Component
public class UserEntityToModelMapping {

      public UserModel EntityToModelMapping(UserEntity userEntity) throws JsonMappingException, JsonProcessingException {
        
        UserModel userModel = new UserModel();
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        userModel.setUsername(userEntity.getUsername());
        userModel.setPassword(userEntity.getPassword());
        userModel.setStatus(userEntity.getStatus());
        userModel.setCreatedBy(userEntity.getCreatedBy());
        userModel.setUpdatedBy(userEntity.getUpdatedBy());
        userModel.setCreatedAt(timestamp);
        userModel.setUpdatedAt(timestamp);
        userModel.setRole(userEntity.getRole());
        return userModel;
      }


}
