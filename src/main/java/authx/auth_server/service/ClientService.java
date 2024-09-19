package authx.auth_server.service;

import authx.auth_server.model.ClientModel;
import lombok.RequiredArgsConstructor;

import java.time.Duration;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ClientService {

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private final PasswordEncoder passwordEncoder;


    public ClientModel RegisterClient(ClientModel clientModel){

        if (registeredClientRepository.findByClientId(clientModel.getClientId())==null) {

				TokenSettings tokenSettings=TokenSettings.builder()
				.accessTokenTimeToLive(Duration.ofMinutes(clientModel.getAccessTokenTimeToLive()))
                .refreshTokenTimeToLive(Duration.ofHours(clientModel.getRefreshTokenTimeToLive()))
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                .reuseRefreshTokens(true)  
                .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                .build();
				RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
					.clientId(clientModel.getClientId())
					.clientSecret(passwordEncoder.encode(clientModel.getClientSecret()))
					.clientName(clientModel.getClientName())
					.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
					.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
					.postLogoutRedirectUri("http://127.0.0.1:8080/")
					.scope(clientModel.getScope())
					.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
					.tokenSettings(tokenSettings)
					.build();
					registeredClientRepository.save(oidcClient);
			}

        return  clientModel;
    }
}
