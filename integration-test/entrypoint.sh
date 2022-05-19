#!/usr/bin/env bash

# authentication
export PULSAR_PREFIX_authenticationEnabled=true
export PULSAR_PREFIX_authenticationProviders=org.apache.pulsar.broker.authentication.AuthenticationProviderToken
export PULSAR_PREFIX_tokenSecretKey=file:///pulsar/conf/my-secret.key

# authorization for broker
export PULSAR_PREFIX_authorizationEnabled=true
export PULSAR_PREFIX_superUserRoles=admin
export PULSAR_PREFIX_authorizationProvider=com.github.nodece.pulsar.casbin.authz.AuthorizationProvider

# authorization for client
export PULSAR_PREFIX_brokerClientAuthenticationPlugin=org.apache.pulsar.client.impl.auth.AuthenticationToken
export PULSAR_PREFIX_brokerClientAuthenticationParameters={"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.mAEZVpz87oZ7vXsqLl-Ue8P9I4SOhqIF7nf8n1f5TZc"} # admin role

# apply the env to standalone.config
python3 /pulsar/bin/apply-config-from-env.py /pulsar/conf/standalone.conf

# start standalone
/pulsar/bin/pulsar standalone -nfw
