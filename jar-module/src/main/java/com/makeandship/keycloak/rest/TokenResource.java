package com.makeandship.keycloak.rest;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.models.KeycloakSession;

import com.makeandship.keycloak.CredentialsRepresentation;
import com.makeandship.keycloak.spi.TokenService;
import com.makeandship.keycloak.spi.impl.TokenServiceImpl;

public class TokenResource {

    private final KeycloakSession session;
    
    public TokenResource(KeycloakSession session) {
        this.session = session;
    }
    
    @POST
    @Path("token")
    @NoCache
    @Consumes(MediaType.APPLICATION_JSON)
    public Response authenticate(CredentialsRepresentation rep) {
        TokenService service = new TokenServiceImpl(session);
        return service.authenticate(rep);
    }

}
