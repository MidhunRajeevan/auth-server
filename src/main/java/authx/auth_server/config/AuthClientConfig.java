package authx.auth_server.config;

import authx.auth_server.entity.Client;
import authx.auth_server.repository.ClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthClientConfig implements UserDetailsService {

    @Autowired
    private  final ClientRepository clientRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Client client= clientRepository.findByClientId(username).orElseThrow(()-> new UsernameNotFoundException("User Details Not Found " +username));
        List<GrantedAuthority> authorities=List.of(new SimpleGrantedAuthority(client.getAuthorities()));
        return new User(client.getClientId(),client.getClientSecret(),authorities);
    }
}
