package com.makeandship.keycloak.spi;

import javax.ws.rs.core.Response;

import org.keycloak.provider.Provider;

import com.makeandship.keycloak.CredentialsRepresentation;

public interface TokenService extends Provider {
    Response authenticate(CredentialsRepresentation rep);
}