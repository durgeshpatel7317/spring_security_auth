#!/bin/zsh

docker-compose -f docker-compose.yml down

mvn clean package -DskipTests

docker build -f Dockerfile -t "spring_auth:1.0.0" .

docker-compose -f docker-compose.yml up
