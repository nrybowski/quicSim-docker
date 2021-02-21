#! /bin/sh -e

docker build -t bcc -f bcc.dockerfile .
docker build -t virtme -f virtme.dockerfile .
