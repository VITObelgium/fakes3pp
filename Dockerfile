# Doing a multi-stage build to make sure to have passing of unittests enforced
FROM docker.io/golang:1.22 AS base

LABEL org.opencontainers.image.source=https://github.com/VITObelgium/fakes3pp
LABEL org.opencontainers.image.description="FakeS3++ proxies S3 compatible APIs and augment them with extra functionality."
LABEL org.opencontainers.image.licenses=AGPL-3.0

COPY go.mod /usr/src/fakes3pp/go.mod
COPY go.sum /usr/src/fakes3pp/go.sum
WORKDIR /usr/src/fakes3pp
# To not have to fetch dependencies each build
RUN go mod download
RUN go mod tidy
ADD . /usr/src/fakes3pp/
ENV NO_TESTING_BACKENDS=container_build
RUN go test -coverprofile cover.out ./...
RUN go vet
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

# If tests pass then build the final stage
FROM scratch

# We need to trust common SSL certificates to get issuer info
COPY --from=base /etc/ssl /etc/ssl
# We need our binary
COPY --from=base /usr/src/fakes3pp/main /fakes3pp

ENTRYPOINT [ "/fakes3pp" ]
