# Stage 1: Build the native executable
FROM quay.io/quarkus/ubi-quarkus-mandrel-builder-image:jdk-17 AS build

COPY --chown=quarkus:quarkus mvnw /code/mvnw
COPY --chown=quarkus:quarkus .mvn /code/.mvn
COPY --chown=quarkus:quarkus pom.xml /code/

USER quarkus
WORKDIR /code

# Download dependencies
RUN ./mvnw -B org.apache.maven.plugins:maven-dependency-plugin:3.6.1:go-offline

COPY src /code/src

RUN ./mvnw package -Pnative -DskipTests

# Stage 2: Create the runtime image
FROM quay.io/quarkus/quarkus-micro-image:2.0

WORKDIR /work/
COPY --from=build /code/target/*-runner /work/application

# Set up proper permissions
RUN chmod 775 /work /work/application \
    && chown -R 1001 /work \
    && chmod -R "g+rwX" /work \
    && chown -R 1001:root /work

EXPOSE 2121
USER 1001

ENTRYPOINT ["./application", "-Dquarkus.http.host=0.0.0.0"]