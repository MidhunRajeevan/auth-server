package authx.auth_server.model;

import java.util.Map;

import lombok.Data;

@Data
public class ClientModel {
    private String clientId;
    private String clientSecret;
    private String clientName;
    private String clientAuthenticationMethod;
    private String authorizationGrantType;
    private String scope;
    private Long accessTokenTimeToLive;
    private Long refreshTokenTimeToLive;

}