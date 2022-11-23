FROM maven:3.8-openjdk-17-slim

RUN mkdir /spring_auth

WORKDIR /spring_auth

COPY ./target/springauthapplication.jar /spring_auth/springauthapplication.jar

CMD ["java", "-jar", "springauthapplication.jar"]