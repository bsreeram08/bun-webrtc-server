# webrtc-bun

WebRTC-Bun is a WebRTC signaling server implementation using Bun runtime. It provides a simple and efficient way to establish WebRTC connections between clients.

## Features

-   WebSocket-based signaling server
-   Support for WebRTC offer/answer exchange
-   ICE candidate exchange
-   Authentication using Auth0
-   Redis integration for storing call and participant information

## Prerequisites

-   Bun runtime
-   Redis server (running on localhost or accessible via network)
-   Auth0 account for authentication

## Installation

```bash
bun install
```

### Configuration

Before running the server, you need to create a .env file in the project root directory and provide the necessary configuration:

```
AUTH0_AUTH_DOMAIN="your-domain.auth0.com"
AUTH0_AUDIENCE="your-auth0-audience"
AUTH0_CERTIFICATE="your-auth0-certificate"

```

Replace your-domain.auth0.com, your-auth0-audience, and your-auth0-certificate with your actual Auth0 configuration values.

### Usage

To run:

```bash
bun serve
```

To run in development:

```bash
bun watch
```

### Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.
