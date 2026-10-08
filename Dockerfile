# Build stage
FROM golang:1.24-alpine AS builder

RUN apk --no-cache add upx

WORKDIR /app

# Download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and build statically linked binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -trimpath -o /identity-service cmd/server/main.go
RUN upx --best --lzma /identity-service

# Production stage
FROM alpine:3.21

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /identity-service /app/identity-service

EXPOSE 8001

CMD ["/app/identity-service"]
