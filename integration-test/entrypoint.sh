#!/usr/bin/env bash

# authentication
export PULSAR_PREFIX_authenticationEnabled=true
export PULSAR_PREFIX_authenticationProviders=org.apache.pulsar.broker.authentication.AuthenticationProviderToken
export PULSAR_PREFIX_tokenSecretKey=file:///pulsar/conf/my-secret.key

# authorization
export PULSAR_PREFIX_authorizationEnabled=true
export PULSAR_PREFIX_superUserRoles=admin
export PULSAR_PREFIX_authorizationProvider=com.github.nodece.pulsar.casbin.authz.AuthorizationProvider

# apply the env to standalone.config
python3 /pulsar/bin/apply-config-from-env.py /pulsar/conf/standalone.conf

# start standalone
/pulsar/bin/pulsar standalone
