FROM golang:1.25-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o ssi-debugger .

FROM alpine:latest
COPY --from=build /app/ssi-debugger /usr/local/bin/
ENTRYPOINT ["ssi-debugger"]
CMD ["wallet", "--auto-accept", "--pid", "--port", "8085"]
