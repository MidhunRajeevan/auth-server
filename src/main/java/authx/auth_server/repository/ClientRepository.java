package authx.auth_server.repository;

import authx.auth_server.entity.ClientEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ClientRepository extends JpaRepository<ClientEntity,Long> {

    Optional<ClientEntity> findByClientId(String clientId);
}
