package authx.auth_server.config;

import authx.auth_server.entity.UserEntity;
import authx.auth_server.mapping.UserEntityToModelMapping;
import authx.auth_server.model.UserModel;
import authx.auth_server.repository.UserRepository;
import lombok.RequiredArgsConstructor;

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

@Service
@RequiredArgsConstructor
public class AuthClientConfig implements UserDetailsService {

    @Autowired
    private  final UserRepository clientRepository;

    @Autowired
    private final UserEntityToModelMapping clientEntityToModelMapping;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserModel clientModel=null;
        UserEntity clientEntity = clientRepository.findByUsername(username).orElseThrow(()-> new UsernameNotFoundException("User Details Not Found " +username));
        try {
           clientModel=clientEntityToModelMapping.EntityToModelMapping(clientEntity);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(clientEntity.getRole()));
        return new User(clientEntity.getUsername(), clientEntity.getPassword(),authorities);
    }

}
