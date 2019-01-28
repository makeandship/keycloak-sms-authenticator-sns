package com.makeandship.keycloak.rest;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

import javax.ws.rs.GET;
import javax.ws.rs.Produces;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class TokenResourceProvider implements RealmResourceProvider {

    private KeycloakSession session;

    public TokenResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new TokenRestResource(session);
    }

    @Override
    public void close() {
    }
}
