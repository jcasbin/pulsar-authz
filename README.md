# Pulsar-authz
![License](https://img.shields.io/github/license/jcasbin/pulsar-authz)
[![Maven Central](https://img.shields.io/maven-central/v/org.casbin.pulsar.authorization/casbin-pulsar-authz.svg)](https://central.sonatype.com/artifact/org.casbin.pulsar.authorization/casbin-pulsar-authz)

An authorization plugin for Apache Pulsar.

**Note:** This plugin requires Pulsar 2.9 or higher.

## Installation

``` xml
<dependency>
    <groupId>org.casbin.pulsar.authorization</groupId>
    <artifactId>casbin-pulsar-authz</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Enable Casbin authorization on Broker

```ini
authorizationEnabled=true
authorizationProvider=org.casbin.pulsar.authorization.AuthorizationProvider
```
