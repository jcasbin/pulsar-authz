package integrations;

import lombok.Cleanup;
import org.apache.pulsar.client.admin.PulsarAdmin;
import org.apache.pulsar.client.api.PulsarClient;
import org.apache.pulsar.client.api.PulsarClientException;
import org.apache.pulsar.client.api.SubscriptionInitialPosition;
import org.apache.pulsar.client.impl.auth.AuthenticationToken;
import org.apache.pulsar.common.policies.data.TenantInfo;
import org.testng.annotations.Test;
import org.testng.collections.Sets;

import java.nio.charset.StandardCharsets;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;

@Test(groups = "integrations")
public class AuthTest {
    private final String ADMIN_TOKEN =
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.mAEZVpz87oZ7vXsqLl-Ue8P9I4SOhqIF7nf8n1f5TZc";
    private final String TEST_USER_TOKEN =
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXVzZXIifQ.0vLQpZTXiYy1muD_6AfknEbuwaKtltTCSy-mr1AC7Qs";

    private PulsarClient createClient(String token) throws PulsarClientException {
        return PulsarClient.builder()
                .serviceUrl("pulsar://localhost:6650")
                .authentication(new AuthenticationToken(token))
                .build();
    }

    private static String getRandomString() {
        var str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        var random = new Random();
        var sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            var number = random.nextInt(62);
            sb.append(str.charAt(number));
        }
        return sb.toString();
    }

    private PulsarAdmin createAdminClient(String token) throws PulsarClientException {
        return PulsarAdmin.builder()
                .serviceHttpUrl("http://localhost:8080")
                .authentication(new AuthenticationToken(token))
                .build();
    }

    @Test
    public void testAdminRole() throws Exception {
        @Cleanup
        var admin = createAdminClient(ADMIN_TOKEN);
        @Cleanup
        var client = createClient(ADMIN_TOKEN);
        var tenant = getRandomString();
        var namespace = getRandomString();
        var nonPartitionedTopic = tenant + "/" + namespace + "/" + getRandomString();
        var partitionedTopic = tenant + "/" + namespace + "/" + getRandomString();

        admin.tenants()
                .createTenant(tenant, TenantInfo.builder().allowedClusters(Sets.newHashSet("standalone")).build());
        admin.namespaces().createNamespace(tenant + "/" + namespace);

        admin.topics().createPartitionedTopic(partitionedTopic, 3);
        admin.topics().createNonPartitionedTopic(nonPartitionedTopic);

        var producer = client.newProducer().topic(partitionedTopic).create();
        producer.send("hello".getBytes(StandardCharsets.UTF_8));
        var consumer = client.newConsumer().topic(partitionedTopic)
                .subscriptionInitialPosition(SubscriptionInitialPosition.Earliest)
                .subscriptionName(getRandomString())
                .subscribe();
        assertThat(consumer.receive()).isNotNull();
        producer.close();
        consumer.close();

        producer = client.newProducer().topic(nonPartitionedTopic).create();
        producer.send("hello".getBytes(StandardCharsets.UTF_8));
        consumer = client.newConsumer().topic(nonPartitionedTopic)
                .subscriptionInitialPosition(SubscriptionInitialPosition.Earliest)
                .subscriptionName(getRandomString())
                .subscribe();
        assertThat(consumer.receive()).isNotNull();
        producer.close();
        consumer.close();
    }
}
