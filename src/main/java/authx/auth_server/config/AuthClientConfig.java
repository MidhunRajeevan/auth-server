package authx.auth_server.config;

import authx.auth_server.entity.ClientEntity;
import authx.auth_server.mapping.ClientEntityToModelMapping;
import authx.auth_server.model.Authorities;
import authx.auth_server.model.ClientModel;
import authx.auth_server.repository.ClientRepository;
import lombok.RequiredArgsConstructor;

import org.hibernate.mapping.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthClientConfig implements UserDetailsService {

    @Autowired
    private  final ClientRepository clientRepository;

    @Autowired
    private final ClientEntityToModelMapping clientEntityToModelMapping;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        ClientModel clientModel=null;
        ClientEntity clientEntity = clientRepository.findByClientId(username).orElseThrow(()-> new UsernameNotFoundException("User Details Not Found " +username));
        try {
           clientModel=clientEntityToModelMapping.EntityToModelMapping(clientEntity);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        List<GrantedAuthority> authorities = extractAuthorities(clientModel.getAuthorities());
        return new User(clientEntity.getClientId(), clientEntity.getClientSecret(),authorities);
    }

    private List<GrantedAuthority> extractAuthorities(List<Authorities> authorities) {
        return authorities.stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getName()))
                .collect(Collectors.toList());
    }
}
