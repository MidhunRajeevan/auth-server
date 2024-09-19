package authx.auth_server.model;

import lombok.Data;

import java.sql.Timestamp;

@Data
public class UserModel {
    private long id;
    private String username;
    private String password;
    private String role;
    private String status;
    private String createdBy;
    private String updatedBy;
    private Timestamp createdAt;
    private Timestamp updatedAt;
}
