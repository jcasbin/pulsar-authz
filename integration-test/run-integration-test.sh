#!/usr/bin/env bash

set -e

ROOT=$(git rev-parse --show-toplevel)
cd "${ROOT}"

mvn -B clean package -DskipTests
docker-compose -f integration-test/docker-compose.yaml up --remove-orphan --build --force-recreate -d

CONTAINER_NAME="casbin-pulsar-authz-intergation-test"
PULSAR_ADMIN="docker exec -d ${CONTAINER_NAME} /pulsar/bin/pulsar-admin"

echo "Waiting for Pulsar service ..."
until curl http://localhost:8080/metrics > /dev/null 2>&1 ; do sleep 1; done
echo "Pulsar service available"

docker-compose -f integration-test/docker-compose.yaml down
