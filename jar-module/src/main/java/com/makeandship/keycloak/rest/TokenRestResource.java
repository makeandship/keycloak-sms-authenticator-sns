package com.makeandship.keycloak.rest;

import javax.ws.rs.Path;

import org.keycloak.models.KeycloakSession;

public class TokenRestResource {

    private final KeycloakSession session;
    
    public TokenRestResource(KeycloakSession session) {
        this.session = session;
    }
    
    @Path("protocol/openid-connect")
    public TokenResource getTokenResource() {
        return new TokenResource(session);
    }

}