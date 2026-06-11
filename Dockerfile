FROM golang:1.21-alpine AS builder
WORKDIR /app
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.buildVersion=${VERSION} -X main.buildCommit=${COMMIT} -X main.buildTime=${BUILD_TIME}" -o gaze-docker .

FROM alpine:3.19
RUN apk add --no-cache docker-cli
COPY --from=builder /app/gaze-docker /usr/local/bin/gaze-docker
EXPOSE 8080
ENTRYPOINT ["gaze-docker"]
