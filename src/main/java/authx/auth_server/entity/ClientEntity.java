package authx.auth_server.entity;

import jakarta.persistence.*;
import lombok.Data;
import org.hibernate.annotations.Type;

import com.vladmihalcea.hibernate.type.json.JsonBinaryType;

import java.sql.Timestamp;

@Data
@Entity
@Table(name = "clients")
public class ClientEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name="id")
    private  long id;

    @Column(name = "client_id")
    private String clientId;

    @Column(name = "client_secret")
    private String clientSecret;


    @Type(JsonBinaryType.class)
    @Column(name = "scope", columnDefinition = "jsonb")
    private String scope;

    @Column(name = "authorized_grant_types")
    private String authorizedGrantTypes;

    @Column(name = "authorities")
    private String authorities;

    @Column(name = "access_token_validity")
    private Integer accessTokenValidity;

    @Column(name = "refresh_token_validity")
    private Integer refreshTokenValidity;

    @Type(JsonBinaryType.class)
    @Column(name = "additional_information", columnDefinition = "jsonb")
    private String additionalInformation;

    @Column(name="status")
    private  String status;

    @Column(name = "created_by")
    private String createdBy;

    @Column(name = "updated_by")
    private String updatedBy;

    @Column(name = "created_at")
    private Timestamp createdAt;

    @Column(name = "updated_at")
    private Timestamp updatedAt;

}
