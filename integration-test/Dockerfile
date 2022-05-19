FROM apachepulsar/pulsar:latest

COPY target/*.jar /pulsar/lib/
COPY integration-test/my-secret.key /pulsar/conf/

COPY integration-test/entrypoint.sh /
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
