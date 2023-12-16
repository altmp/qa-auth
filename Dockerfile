# Build Stage
FROM golang:latest AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy everything from the current directory to the Working Directory inside the container
COPY . .

# Build the Go app
RUN go build -o qa-auth

# Final Stage
FROM alpine:latest  

WORKDIR /root/

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/qa-auth .

# Command to run the executable
CMD ["./qa-auth"]
