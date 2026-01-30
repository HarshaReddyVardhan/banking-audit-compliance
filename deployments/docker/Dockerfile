# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

# Set working directory to project root equivalent in container
WORKDIR /app

# Copy shared library
COPY banking-shared-go ./banking-shared-go

# Copy service code
COPY banking-audit-compliance ./banking-audit-compliance

# Set working directory to service
WORKDIR /app/banking-audit-compliance

# Download dependencies (now it can find ../banking-shared-go)
RUN go mod download

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -o /app/server \
    ./cmd/server

# Runtime stage
FROM gcr.io/distroless/static:nonroot

# Copy binary
COPY --from=builder /app/server /server

# Use non-root user
USER nonroot:nonroot

# Expose port
EXPOSE 8086

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/server", "-health-check"]

# Run the application
ENTRYPOINT ["/server"]
