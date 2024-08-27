# Use the official Rust image as a base
FROM rust:1.69 as builder

# Create a new directory for the project
WORKDIR /usr/src/app

# Copy the current directory contents into the container
COPY . .

# Build the application in release mode
RUN cargo build --release

# Use a minimal base image to run the application
FROM debian:buster-slim

# Install RocksDB dependencies
RUN apt-get update && apt-get install -y librocksdb-dev && rm -rf /var/lib/apt/lists/*

# Copy the built binary from the builder stage
COPY --from=builder /usr/src/app/target/release/zkp_app /usr/local/bin/zkp_app

# Expose the application port
EXPOSE 8000

# Set the default command to run the application
CMD ["zkp_app"]