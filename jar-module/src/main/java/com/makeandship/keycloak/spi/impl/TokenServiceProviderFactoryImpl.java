package com.makeandship.keycloak.spi.impl;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

import com.makeandship.keycloak.spi.TokenService;
import com.makeandship.keycloak.spi.TokenServiceProviderFactory;

public class TokenServiceProviderFactoryImpl implements TokenServiceProviderFactory {

    @Override
    public TokenService create(KeycloakSession session) {
        return new TokenServiceImpl(session);
    }

    @Override
    public void init(Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "tokenServiceImpl";
    }

}