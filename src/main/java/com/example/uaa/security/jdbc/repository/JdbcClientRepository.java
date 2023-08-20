package com.example.uaa.security.jdbc.repository;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface JdbcClientRepository extends RegisteredClientRepository {

}
