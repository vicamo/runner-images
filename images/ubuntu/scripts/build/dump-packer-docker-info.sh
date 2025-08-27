#!/bin/sh

id -a

echo "##################################################"

ls -al /tmp

echo "##################################################"

mount

echo "##################################################"

CONTAINER_ID="$(docker ps --last 1 --format '{{ .ID }}')"
docker inspect "${CONTAINER_ID}"

echo "##################################################"

docker exec "${CONTAINER_ID}" id -a
docker exec "${CONTAINER_ID}" ls -al /tmp

echo "##################################################"

cat /sys/module/apparmor/parameters/enabled
sudo aa-status
