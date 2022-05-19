FROM apachepulsar/pulsar:latest

COPY target/*-shade.jar /pulsar/lib/
COPY integration-test/my-secret.key /pulsar/conf/

RUN mkdir /pulsar/casbin-test
COPY integration-test/entrypoint.sh /pulsar/casbin-test/

ENTRYPOINT ["/pulsar/casbin-test/entrypoint.sh"]
