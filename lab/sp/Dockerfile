# Builds the lab SP into a static binary on an empty base image.
FROM golang:1.27.3 AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /sp .

FROM scratch
COPY --from=build /sp /sp
# Inside the container it must listen on all interfaces; docker-compose
# still publishes the port on 127.0.0.1 only.
ENTRYPOINT ["/sp", "-listen", "0.0.0.0:8081"]
