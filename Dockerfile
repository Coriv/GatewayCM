FROM openjdk:17-oracle
RUN microdnf install findutils
WORKDIR /app
COPY . .
RUN ./gradlew build
CMD ["java", "-jar", "build/libs/GatewayCM-0.0.1-SNAPSHOT.jar", "--spring.cloud.config.uri=http://config:8888", "--eureka.client.serviceUrl.defaultZone=http://configUser:configPass@discovery:8082/eureka/"]