package org.casbin.pulsar.authorization;

import static com.google.common.base.Preconditions.checkNotNull;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.AsyncLoadingCache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.google.common.util.concurrent.MoreExecutors;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import java.util.stream.Collectors;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.util.Strings;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.AuthenticationDataSource;
import org.apache.pulsar.broker.cache.ConfigurationCacheService;
import org.apache.pulsar.broker.resources.PulsarResources;
import org.apache.pulsar.broker.resources.TenantResources;
import org.apache.pulsar.common.naming.NamespaceName;
import org.apache.pulsar.common.naming.TopicName;
import org.apache.pulsar.common.policies.data.AuthAction;
import org.apache.pulsar.common.policies.data.NamespaceOperation;
import org.apache.pulsar.common.policies.data.PolicyName;
import org.apache.pulsar.common.policies.data.PolicyOperation;
import org.apache.pulsar.common.policies.data.TenantOperation;
import org.apache.pulsar.common.policies.data.TopicOperation;
import org.apache.pulsar.metadata.api.MetadataStore;
import org.casbin.jcasbin.main.SyncedEnforcer;
import org.casbin.jcasbin.model.Model;

@Slf4j
public class AuthorizationProvider implements org.apache.pulsar.broker.authorization.AuthorizationProvider {
    private static final String DEFAULT_FILL = "*";
    private static final String TYPE_POLICY = "p";
    private static final String TYPE_GROUPING_POLICY = "g";
    private ServiceConfiguration config = null;
    private MetadataStore metadataStore;
    private TenantResources tenantResources;
    private String metadataBasePath = "/casbin";
    private String modelText = "[request_definition]\n"
            + "r = subject, domain, object, action, scope\n"
            + "\n"
            + "[policy_definition]\n"
            + "p = subject, domain, object, action, scope\n"
            + "\n"
            + "[role_definition]\n"
            + "g = _, _, _\n"
            + "\n"
            + "[policy_effect]\n"
            + "e = some(where (p.eft == allow))\n"
            + "\n"
            + "[matchers]\n"
            + "m = g(r.subject, p.subject, r.domain) && r.domain == p.domain && r.object == p.object && "
            + "keyMatch(r.action, p.action) && keyMatch(r.scope, p.scope)";
    private AsyncLoadingCache<String, Optional<SyncedEnforcer>> enforcerCache;
    private final ObjectMapper mapper = new ObjectMapper();

    private Optional<MetadataStore> getConfigurationMetadataStore(Object object) {
        try {
            var field = object.getClass().getDeclaredField("configurationMetadataStore");
            field.setAccessible(true);
            return (Optional<MetadataStore>) field.get(object);
        } catch (Exception e) {
            log.error("Cannot get the configurationMetadataStore", e);
            return Optional.empty();
        }
    }

    private TenantResources getTenantResources(Object object) {
        try {
            var field = object.getClass().getDeclaredField("tenantResources");
            field.setAccessible(true);
            return (TenantResources) field.get(object);
        } catch (Exception e) {
            log.error("Cannot get the tenantResources", e);
            return null;
        }
    }

    @Override
    public void initialize(ServiceConfiguration conf, PulsarResources pulsarResources) {
        newProvider(conf, getConfigurationMetadataStore(pulsarResources), getTenantResources(pulsarResources));
    }

    @Override
    public void initialize(ServiceConfiguration conf, ConfigurationCacheService configCache) {
        // NOTE: Not sure if it is fully compatible.
        newProvider(conf, getConfigurationMetadataStore(configCache), getTenantResources(configCache));
    }

    @SneakyThrows
    private void newProvider(ServiceConfiguration conf, Optional<MetadataStore> configurationMetadataStore,
                             TenantResources tenantResources) {
        checkNotNull(conf, "ServiceConfiguration cannot be null");
        final var metadataStoreError =
                "ConfigurationMetadataStore cannot be null, this authorization provider requires MetadataStore support";
        checkNotNull(configurationMetadataStore, metadataStoreError);
        checkNotNull(tenantResources, "TenantResources cannot be null");

        config = conf;
        metadataStore = configurationMetadataStore.orElseThrow(() -> new IllegalArgumentException(metadataStoreError));
        this.tenantResources = tenantResources;

        var modelPath = StringUtils.defaultString((String) conf.getProperty("enforcerModelPath"));
        if (Strings.isNotEmpty(modelPath)) {
            log.info("Load model from enforcerModelPath: {}", modelPath);
            URI uri = new URI(modelPath);
            InputStream in = uri.toURL().openStream();
            StringWriter writer = new StringWriter();
            IOUtils.copy(in, writer, StandardCharsets.UTF_8.name());
            modelText = writer.toString();
        }

        log.debug("Model text: {}", modelText);
        // Verify the model.
        new Model().loadModelFromText(modelText);

        String enforcerMetadataPath = StringUtils.defaultString((String) conf.getProperty("enforcerMetadataPath"));
        if (Strings.isNotEmpty(modelPath)) {
            if (modelPath.equals("/")) {
                throw new IllegalArgumentException("enforcerMetadataPath cannot be equals '/'");
            }
            this.metadataBasePath =
                    !enforcerMetadataPath.startsWith("/") ? "/" + enforcerMetadataPath : enforcerMetadataPath;
        }
        log.info("Enforcer metadata path: {}", metadataBasePath);

        enforcerCache = Caffeine.newBuilder()
                .executor(MoreExecutors.directExecutor())
                .buildAsync((subject, executor) -> loadEnforcer(subject));

        metadataStore.registerListener(notification -> {
            var path = notification.getPath();

            if (!path.startsWith(metadataBasePath) || path.equals(metadataBasePath)) {
                return;
            }

            switch (notification.getType()) {
                case Created:
                case Deleted:
                case Modified:
                    var split = path.substring(1).split("/");
                    var role = split[split.length - 1];
                    log.info("{} path data has been changed, discard cache", path);
                    enforcerCache.synchronous().invalidate(role);
            }
        });

        log.info("Initialized successfully");
    }

    private String getSubjectPath(String subject) {
        return metadataBasePath + "/" + subject;
    }

    private byte[] writePolicyAsBytes(Set<List<String>> policy) throws JsonProcessingException {
        return mapper.writeValueAsBytes(policy);
    }

    private Set<List<String>> readPolicyFromBytes(byte[] data) throws IOException {
        return mapper.readValue(data, new TypeReference<>() {
        });
    }

    private CompletableFuture<Optional<SyncedEnforcer>> loadEnforcer(String subject) {
        final var path = getSubjectPath(subject);
        return metadataStore.get(path).thenApply(res -> {
            if (res.isEmpty()) {
                log.debug("No policy for subject {}", subject);
                return Optional.empty();
            }

            Set<List<String>> policy;
            try {
                policy = readPolicyFromBytes(res.get().getValue());
            } catch (IOException e) {
                log.error("Cannot read policy from bytes", e);
                throw new IllegalArgumentException(e);
            }

            var m = new Model();
            m.loadModelFromText(modelText);
            var e = new SyncedEnforcer(m);
            policy.forEach(n -> {
                var type = n.get(0);
                switch (type) {
                    case TYPE_POLICY:
                        e.addPolicy(n);
                        break;
                    case TYPE_GROUPING_POLICY:
                        e.addGroupingPolicy(n);
                        break;
                    default:
                        throw new IllegalArgumentException("Policy type " + type + " is supported");
                }
            });
            return Optional.of(e);
        });
    }

    private CompletableFuture<Void> updatePolicy(String subject,
                                                 Function<Set<List<String>>, Set<List<String>>> updateFn) {
        final var path = getSubjectPath(subject);
        return metadataStore.get(path).thenCompose(n -> {
            Set<List<String>> policy;
            if (n.isEmpty()) {
                policy = Sets.newLinkedHashSet();
            } else {
                try {
                    policy = readPolicyFromBytes(n.get().getValue());
                } catch (IOException e) {
                    log.error("Cannot read policy from bytes", e);
                    throw new IllegalArgumentException(e);
                }
            }
            policy = updateFn.apply(policy);
            try {
                var data = writePolicyAsBytes(policy);
                return metadataStore.put(path, data, Optional.empty())
                        .thenApply(__ -> null);
            } catch (JsonProcessingException e) {
                log.error("Cannot write policy to bytes", e);
                throw new IllegalArgumentException(e);
            }
        });
    }

    private CompletableFuture<Boolean> internalEnforceAsync(
            @NonNull String subject,
            @NonNull String domain,
            @NonNull String object,
            @NonNull String action,
            @NonNull String scope) {
        var request = Lists.newArrayList(subject, domain, object, action, scope);
        return enforcerCache.get(subject).thenApply(enforcer -> {
            if (enforcer.isEmpty()) {
                return false;
            }
            return enforcer.get().enforce(request);
        });
    }

    private CompletableFuture<Boolean> enforceAdminAccessAsync(String tenantName, String role,
                                                               AuthenticationDataSource authData) {
        return isSuperUser(role, authData, config).thenCompose(isSuperUser -> {
            if (isSuperUser != null && isSuperUser) {
                return CompletableFuture.completedFuture(true);
            }
            return tenantResources.getTenantAsync(tenantName).thenCompose(op -> {
                if (op.isPresent()) {
                    return isTenantAdmin(tenantName, role, op.get(), authData);
                } else {
                    return CompletableFuture.completedFuture(false);
                }
            });
        });
    }

    private CompletableFuture<Boolean> enforceTopicNameAsync(@NonNull String subject, @NonNull TopicName topicName,
                                                             @NonNull String action, @NonNull String scope,
                                                             @NonNull AuthenticationDataSource authenticationData) {
        return enforceAdminAccessAsync(topicName.getTenant(), subject, authenticationData).thenCompose(
                (isAuthorized) -> {
                    if (isAuthorized != null && isAuthorized) {
                        return CompletableFuture.completedFuture(true);
                    }
                    return internalEnforceAsync(subject, topicName.getNamespace(), topicName.getPartitionedTopicName(),
                            action, scope);
                }).whenComplete((ok, ex) -> {
            if (ex != null) {
                log.error("Failed to enforce {}", Lists.newArrayList(subject, topicName, action, scope), ex);
                return;
            }
            if (log.isDebugEnabled()) {
                log.debug("Enforce {} -> {}", Lists.newArrayList(subject, topicName, action, scope), ok);
            }
        });
    }

    private CompletableFuture<Boolean> enforceNamespaceAsync(
            @NonNull String subject,
            @NonNull NamespaceName namespaceName,
            @NonNull String object,
            @NonNull String action,
            @NonNull AuthenticationDataSource authenticationData) {
        return enforceAdminAccessAsync(namespaceName.getTenant(), subject, authenticationData).thenCompose(
                (isAuthorized) -> {
                    if (isAuthorized != null && isAuthorized) {
                        return CompletableFuture.completedFuture(true);
                    }
                    return internalEnforceAsync(subject, namespaceName.toString(), object, action, DEFAULT_FILL);
                }).whenComplete((ok, ex) -> {
            if (ex != null) {
                log.error("Failed to enforce {}", Lists.newArrayList(subject, namespaceName, action), ex);
                return;
            }
            if (log.isDebugEnabled()) {
                log.debug("Enforce {} -> {}", Lists.newArrayList(subject, namespaceName, action), ok);
            }
        });
    }

    private CompletableFuture<Void> addPolicy(Set<String> subjects, TopicName topicName, Set<String> actions) {
        var data = subjects.stream()
                .collect(Collectors.groupingBy(subject -> subject,
                        Collectors.flatMapping(subject -> actions.stream().map(action ->
                                        Lists.newArrayList(
                                                TYPE_POLICY,
                                                subject,
                                                topicName.getNamespaceObject().toString(),
                                                topicName.getPartitionedTopicName(),
                                                action,
                                                DEFAULT_FILL)
                                ),
                                Collectors.toSet())));
        var futures = new ArrayList<CompletableFuture<Void>>();
        data.forEach((key, value) -> {
            futures.add(updatePolicy(key, policy -> {
                policy.addAll(value);
                return policy;
            }));
        });

        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).whenComplete((__, ex) -> {
            if (ex == null) {
                log.info("Successfully granted access for role {} on topic {}: {} {}", subjects,
                        topicName.getPartitionedTopicName(), actions, DEFAULT_FILL);
            } else {
                log.error("Failed to grant access for role {} on topic {}: {} {}", subjects,
                        topicName.getPartitionedTopicName(), actions, DEFAULT_FILL, ex);
            }
        });
    }

    private CompletableFuture<Void> addPolicy(Set<String> subjects, NamespaceName namespaceName, Set<String> actions,
                                              String scope) {
        var data = subjects.stream()
                .collect(Collectors.groupingBy(subject -> subject,
                        Collectors.flatMapping(subject -> actions.stream().map(action ->
                                        Lists.newArrayList(
                                                TYPE_POLICY,
                                                subject,
                                                namespaceName.toString(),
                                                DEFAULT_FILL,
                                                action,
                                                scope)
                                ),
                                Collectors.toSet())));
        var futures = new ArrayList<CompletableFuture<Void>>();
        data.forEach((key, value) -> {
            futures.add(updatePolicy(key, policy -> {
                policy.addAll(value);
                return policy;
            }));
        });

        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).whenComplete((__, ex) -> {
            if (ex == null) {
                log.info("Successfully granted access for role {} on namespace {}: {} {}", subjects, namespaceName,
                        actions, scope);
            } else {
                log.error("Failed to grant access for role {} on namespace {}: {} {}", subjects, namespaceName, actions,
                        scope, ex);
            }
        });
    }

    private CompletableFuture<Void> removePolicy(String subject, TopicName topicName, String action,
                                                 String scope) {
        List<String> rule = Lists.newArrayList(TYPE_POLICY, subject, topicName.getNamespaceObject().toString(),
                topicName.getPartitionedTopicName(), action, scope);
        return updatePolicy(subject, (policy) -> {
            policy.remove(rule);
            return policy;
        }).whenComplete((__, ex) -> {
            if (ex == null) {
                log.info("Successfully revoked access for role {} on topic {}: {} {}", subject,
                        topicName.getPartitionedTopicName(), action, scope);
            } else {
                log.error("Failed to revoke access for role {} on topic {}: {} {}", subject,
                        topicName.getPartitionedTopicName(), action, scope, ex);
            }
        });
    }

    private CompletableFuture<Void> removePolicy(String subject, NamespaceName namespaceName, String action,
                                                 String scope) {
        var rule = Lists.newArrayList(TYPE_POLICY, subject, namespaceName.toString(), DEFAULT_FILL, action,
                scope);
        return updatePolicy(subject, (policy) -> {
            policy.remove(rule);
            return policy;
        }).whenComplete((__, ex) -> {
            if (ex == null) {
                log.info("Successfully revoked access for role {} on namespace {}: {} {}", subject,
                        namespaceName, action, scope);
            } else {
                log.error("Failed to revoke access for role {} on namespace {}: {} {}", subject,
                        namespaceName, action, scope, ex);
            }
        });
    }

    @Override
    public CompletableFuture<Boolean> canProduceAsync(
            TopicName topicName, String role, AuthenticationDataSource authenticationData) {
        return enforceTopicNameAsync(role, topicName, AuthAction.produce.name(), DEFAULT_FILL, authenticationData);
    }

    @Override
    public CompletableFuture<Boolean> canConsumeAsync(
            TopicName topicName, String role, AuthenticationDataSource authenticationData, String subscription) {
        return enforceTopicNameAsync(role, topicName, AuthAction.consume.name(), subscription, authenticationData);
    }

    @Override
    public CompletableFuture<Boolean> canLookupAsync(
            TopicName topicName, String role, AuthenticationDataSource authenticationData) {
        return canProduceAsync(topicName, role, authenticationData).thenCompose((produceAuthorized) -> {
            if (produceAuthorized) {
                return CompletableFuture.completedFuture(true);
            }
            return canConsumeAsync(topicName, role, authenticationData, DEFAULT_FILL);
        });
    }

    @Override
    public CompletableFuture<Void> grantPermissionAsync(
            TopicName topicName, Set<AuthAction> actions, String role, String authDataJson) {
        return addPolicy(Sets.newHashSet(role), topicName,
                actions.stream().map(Enum::name).collect(Collectors.toSet()));
    }

    @Override
    public CompletableFuture<Void> grantPermissionAsync(
            NamespaceName namespaceName, Set<AuthAction> actions, String role, String authDataJson) {
        return addPolicy(Sets.newHashSet(role), namespaceName,
                actions.stream().map(Enum::name).collect(Collectors.toSet()), DEFAULT_FILL);
    }

    @Override
    public CompletableFuture<Void> grantSubscriptionPermissionAsync(
            NamespaceName namespace, String subscriptionName, Set<String> roles, String authDataJson) {
        return addPolicy(roles, namespace, Sets.newHashSet(AuthAction.consume.name()), subscriptionName);
    }

    @Override
    public CompletableFuture<Void> revokeSubscriptionPermissionAsync(
            NamespaceName namespace, String subscriptionName, String role, String authDataJson) {
        return removePolicy(role, namespace, AuthAction.consume.name(), subscriptionName);
    }

    @Override
    public CompletableFuture<Boolean> allowFunctionOpsAsync(
            NamespaceName namespaceName, String role, AuthenticationDataSource authenticationData) {
        return enforceNamespaceAsync(role, namespaceName, DEFAULT_FILL, AuthAction.functions.name(),
                authenticationData);
    }

    @Override
    public CompletableFuture<Boolean> allowSourceOpsAsync(
            NamespaceName namespaceName, String role, AuthenticationDataSource authenticationData) {
        return enforceNamespaceAsync(role, namespaceName, DEFAULT_FILL, AuthAction.sources.name(), authenticationData);
    }

    @Override
    public CompletableFuture<Boolean> allowSinkOpsAsync(
            NamespaceName namespaceName, String role, AuthenticationDataSource authenticationData) {
        return enforceNamespaceAsync(role, namespaceName, DEFAULT_FILL, AuthAction.sinks.name(), authenticationData);
    }

    @Override
    public CompletableFuture<Boolean> allowTenantOperationAsync(
            String tenantName,
            String role,
            TenantOperation operation,
            AuthenticationDataSource authData) {
        return enforceAdminAccessAsync(tenantName, role, authData).thenCompose(
                (isAuthorized) -> {
                    if (isAuthorized != null && isAuthorized) {
                        return CompletableFuture.completedFuture(true);
                    }
                    return internalEnforceAsync(role, tenantName, DEFAULT_FILL, operation.name(), DEFAULT_FILL);
                }).whenComplete((ok, ex) -> {
            if (ex != null) {
                log.error("Failed to enforce {}", Lists.newArrayList(role, tenantName, operation), ex);
                return;
            }
            if (log.isDebugEnabled()) {
                log.debug("Enforce {} -> {}", Lists.newArrayList(role, tenantName, operation), ok);
            }
        });
    }

    @Override
    public CompletableFuture<Boolean> allowNamespacePolicyOperationAsync(
            NamespaceName namespaceName,
            PolicyName policy,
            PolicyOperation operation,
            String role,
            AuthenticationDataSource authData) {
        return enforceNamespaceAsync(role, namespaceName, policy.name(), operation.name(), authData);
    }

    @Override
    public CompletableFuture<Boolean> allowTopicOperationAsync(TopicName topicName,
                                                               String role,
                                                               TopicOperation operation,
                                                               AuthenticationDataSource authData) {
        return enforceTopicNameAsync(role, topicName, operation.name(), DEFAULT_FILL, authData).thenCompose(ok -> {
            if (ok != null && ok) {
                return CompletableFuture.completedFuture(true);
            }
            switch (operation) {
                case LOOKUP:
                case GET_STATS:
                    return canLookupAsync(topicName, role, authData);
                case PRODUCE:
                    return canProduceAsync(topicName, role, authData);
                case GET_SUBSCRIPTIONS:
                case CONSUME:
                case SUBSCRIBE:
                case UNSUBSCRIBE:
                case SKIP:
                case EXPIRE_MESSAGES:
                case PEEK_MESSAGES:
                case RESET_CURSOR:
                case SET_REPLICATED_SUBSCRIPTION_STATUS:
                    return canConsumeAsync(topicName, role, authData, authData.getSubscription());
                case TERMINATE:
                case COMPACT:
                case OFFLOAD:
                case UNLOAD:
                case ADD_BUNDLE_RANGE:
                case GET_BUNDLE_RANGE:
                case DELETE_BUNDLE_RANGE:
                default:
                    return CompletableFuture.completedFuture(false);
            }
        });
    }

    @Override
    public CompletableFuture<Boolean> allowTopicPolicyOperationAsync(TopicName topicName,
                                                                     String role,
                                                                     PolicyName policyName,
                                                                     PolicyOperation policyOperation,
                                                                     AuthenticationDataSource authData) {
        return enforceTopicNameAsync(role, topicName, policyName.name(), policyOperation.name(), authData);
    }

    @Override
    public CompletableFuture<Boolean> allowNamespaceOperationAsync(NamespaceName namespaceName, String role,
                                                                   NamespaceOperation operation,
                                                                   AuthenticationDataSource authData) {
        return enforceNamespaceAsync(role, namespaceName, DEFAULT_FILL, operation.name(), authData).thenCompose(ok -> {
            if (ok != null && ok) {
                return CompletableFuture.completedFuture(true);
            }

            switch (operation) {
                case PACKAGES:
                    return enforceNamespaceAsync(role, namespaceName, DEFAULT_FILL, AuthAction.packages.name(),
                            authData);
                case GET_TOPIC:
                case GET_TOPICS:
                case GET_BUNDLE:
                    return enforceNamespaceAsync(role, namespaceName, DEFAULT_FILL, AuthAction.consume.name(),
                            authData).thenCompose(
                            (n) -> enforceNamespaceAsync(role, namespaceName, DEFAULT_FILL,
                                    AuthAction.produce.name(), authData));
                case UNSUBSCRIBE:
                case CLEAR_BACKLOG:
                    return enforceNamespaceAsync(role, namespaceName, DEFAULT_FILL, AuthAction.consume.name(),
                            authData);
                case CREATE_TOPIC:
                case DELETE_TOPIC:
                case ADD_BUNDLE:
                case DELETE_BUNDLE:
                case GRANT_PERMISSION:
                case GET_PERMISSION:
                case REVOKE_PERMISSION:
                default:
                    return CompletableFuture.completedFuture(false);
            }
        });
    }

    @Override
    public void close() throws IOException {
    }
}
