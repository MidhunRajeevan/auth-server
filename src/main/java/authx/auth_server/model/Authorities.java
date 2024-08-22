package authx.auth_server.model;

import java.util.Map;

import lombok.Data;

@Data
public class Authorities {
    private String appId;
    private String name;
    private Map<String, Boolean> permissions;
}