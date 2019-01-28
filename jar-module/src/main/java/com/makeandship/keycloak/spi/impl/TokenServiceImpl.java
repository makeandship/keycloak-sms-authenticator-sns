package com.makeandship.keycloak.spi.impl;

import javax.ws.rs.core.Response;

import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.endpoints.TokenEndpoint;

import com.makeandship.keycloak.CredentialsRepresentation;
import com.makeandship.keycloak.spi.TokenService;

public class TokenServiceImpl implements TokenService {

    private final KeycloakSession session;

    public TokenServiceImpl(KeycloakSession session) {
        this.session = session;
        if (getRealm() == null) {
            throw new IllegalStateException("The service cannot accept a session without a realm in its context.");
        }
    }

    protected RealmModel getRealm() {
        return session.getContext().getRealm();
    }

    public void close() {
        // Nothing to do.
    }

    @Override
    public Response authenticate(CredentialsRepresentation rep) {
        TokenManager tokenManager = new TokenManager();
        RealmModel realmModel = session.getContext().getRealm();
        EventBuilder event = new EventBuilder(realmModel, session, null);
        TokenEndpoint endpoint = new TokenEndpoint(tokenManager, realmModel, event);
        return endpoint.resourceOwnerPasswordCredentialsGrant();
    }

}
