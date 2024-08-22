package authx.auth_server.model;

import lombok.Data;

import java.sql.Timestamp;
import java.util.List;
import java.util.Map;

@Data
public class ClientModel {
    private long id;
    private String clientId;
    private String clientSecret;
    private List<Authorities> authorities;
    private String authorizedGrantTypes;
    private Integer accessTokenValidity;
    private Integer refreshTokenValidity;
    private Map<String, Object> additionalInformation;
    private String status;
    private String createdBy;
    private String updatedBy;
    private Timestamp createdAt;
    private Timestamp updatedAt;
}
