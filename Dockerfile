# Doing a multi-stage build to make sure to have passing of unittests enforced
FROM docker.io/golang:1.22 AS base

# Credit check tests
COPY go.mod /usr/src/fakes3pp/go.mod
COPY go.sum /usr/src/fakes3pp/go.sum
WORKDIR /usr/src/fakes3pp
# To not have to fetch dependencies each build
RUN go mod download
RUN go mod tidy
ADD . /usr/src/fakes3pp/
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
