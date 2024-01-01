# Discord Authentication Service

## Overview
This project is a Discord authentication service written in Go. It interfaces with Discord's OAuth2 API to authenticate users and checks if they have specific roles within a Discord guild. The service also interacts with a CDN endpoint to generate and post a new token, based on user authentication.

## Features
- **OAuth2 Integration**: Uses Discord's OAuth2 API for user authentication.
- **Role Verification**: Checks if authenticated users have specific roles in a Discord guild.
- **Token Generation**: Generates a new token upon successful user role verification.
- **HTTP Server**: Runs an HTTP server to handle authentication requests.

## Prerequisites
- Go (latest version recommended)
- A Discord bot token, client ID, and client secret
- Guild ID of the Discord server
- Specific role IDs for verification
- Cloudflare security token for CDN interactions

## Environment Variables
The following environment variables need to be set for the service to function properly:

- `DISCORD_BOT_TOKEN`: Your Discord bot token.
- `DISCORD_CLIENT_ID`: Your Discord client ID.
- `DISCORD_CLIENT_SECRET`: Your Discord client secret.
- `DISCORD_GUILDS`: Comma-separated list of Discord guild IDs.
- `DISCORD_QA_ROLES`: Comma-separated list of Discord role IDs for authentication.
- `CF_SECURITY_TOKEN`: Security token for Cloudflare CDN interactions.
- `HTTP_HOST`: Host for the HTTP server (e.g., `0.0.0.0`).
- `HTTP_PORT`: Port for the HTTP server (e.g., `5675`).

## Setup
1. Clone the repository to your local machine.
2. Navigate to the project directory.
3. Ensure all required environment variables are set in your environment or a `.env` file.
4. Run the service using `go run main.go`.

## Usage
The service starts an HTTP server that listens for authentication requests. Upon receiving a request, it:

1. Exchanges a provided code for a Discord access token.
2. Retrieves the user's information and verifies their roles in the specified guild.
3. If the user has the required role(s), a new token is generated and sent to a specified CDN endpoint.

## Endpoint
`/auth`: Handles the authentication process and token generation.

## Contributing
Contributions to this project are welcome. Please ensure you follow the code of conduct and submit pull requests for any new features or bug fixes.
