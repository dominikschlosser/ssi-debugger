FROM golang:1.25-alpine AS build
ARG VERSION=dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -ldflags "-s -w -X github.com/dominikschlosser/oid4vc-dev/cmd.Version=${VERSION}" -o oid4vc-dev .

FROM alpine:latest
COPY --from=build /app/oid4vc-dev /usr/local/bin/
ENTRYPOINT ["oid4vc-dev"]
CMD ["wallet", "serve", "--auto-accept", "--pid", "--port", "8085"]
