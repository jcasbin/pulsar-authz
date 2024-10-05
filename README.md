# Pulsar-authz

An authorization plugin for Apache Pulsar.

**Note:** This plugin requires Pulsar 2.9 or higher. 

### Enable Casbin authorization on Broker

```ini
authorizationEnabled=true
authorizationProvider=org.casbin.pulsar.authorization.AuthorizationProvider
```
