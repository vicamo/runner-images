#!/bin/sh

mount

docker inspect "$(docker ps --last 1 --format '{{ .ID }}')"
