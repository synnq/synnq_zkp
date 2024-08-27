# ZKP Proof Generation and Verification

This repository contains a Rocket-based Rust application that generates and verifies zero-knowledge proofs (ZKP) using Bulletproofs. The application uses RocksDB for persistent storage of proofs and verification results.

## Features

- **Generate ZKP Proofs**: Generate zero-knowledge proofs using a secret.
- **Verify ZKP Proofs**: Verify the generated proofs.
- **Store Data in RocksDB**: Persistently store proofs and verification results using RocksDB.
- **Retrieve Receipts**: Retrieve proof and verification results (receipts) using a specific secret.

## Prerequisites

- **Rust**: Ensure that Rust is installed on your system. You can install Rust using `rustup`:
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- **Docker**: Install Docker to build and run the application in a containerized environment.
- **Kubernetes**: (Optional) If you want to deploy the application on Kubernetes, you need a running Kubernetes cluster and `kubectl` installed.

## Setup Instructions

### 1. Local Setup

#### Building the Application

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/zkp-app.git
   cd zkp-app
   ```

2. Build the application:
   ```bash
   cargo build --release
   ```

#### Running the Application Locally

1. Run the application:

   ```bash
   cargo run --release
   ```

2. The application will be accessible at `http://localhost:8000`.

### 2. Docker Setup

#### Building and Running with Docker

1. Build the Docker image:

   ```bash
   docker build -t your_dockerhub_username/zkp-app:latest .
   ```

2. Run the Docker container:

   ```bash
   docker run -p 8000:8000 -v $(pwd)/zkp_rocksdb:/zkp_rocksdb your_dockerhub_username/zkp-app:latest
   ```

3. Access the application at `http://localhost:8000`.

### 3. Kubernetes Setup

#### Deploying to Kubernetes

1. Build and push the Docker image to a container registry:

   ```bash
   docker push your_dockerhub_username/zkp-app:latest
   ```

2. Apply the Kubernetes configuration files:

   ```bash
   kubectl apply -f pv-pvc.yaml
   kubectl apply -f deployment.yaml
   kubectl apply -f service.yaml
   ```

3. Access the application using the service's external IP.

### Endpoints

#### 1. Generate a Proof

- **Endpoint**: `POST /generate`
- **Request**:
  ```json
  {
    "secret": 42
  }
  ```
- **Response**:
  ```json
  {
    "proof": [
      /* proof data here */
    ],
    "blinding": "/* blinding data here */"
  }
  ```

#### 2. Verify a Proof

- **Endpoint**: `POST /verify`
- **Request**:
  ```json
  {
    "proof": [
      /* proof data here */
    ],
    "secret": 42,
    "blinding": "/* blinding data here */"
  }
  ```
- **Response**:
  ```json
  {
    "valid": true // or false
  }
  ```

#### 3. Retrieve a Receipt

- **Endpoint**: `GET /receipt/<secret>`
- **Response**:
  ```json
  {
    "proof": [
      /* proof data here */
    ],
    "blinding": "/* blinding data here */",
    "valid": true // or false
  }
  ```

### Project Structure

- **`main.rs`**: The main entry point of the application.
- **`zkp.rs`**: Contains the logic for generating and verifying ZKP proofs.
- **`Dockerfile`**: Defines the Docker image for the application.
- **`docker-compose.yml`**: Defines the Docker Compose setup for local development.
- **`deployment.yaml`**: Kubernetes Deployment resource for managing Pods.
- **`service.yaml`**: Kubernetes Service resource for exposing the application.
- **`pv-pvc.yaml`**: Kubernetes PersistentVolume and PersistentVolumeClaim resources for RocksDB storage.

### Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

### License

This project is licensed under the MIT License.

---

This `README.md` provides an overview of the project, setup instructions, usage details, and other essential information to get started with the application.
