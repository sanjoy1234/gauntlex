# Spec: User Authentication Service (Go)

## Overview

Implement a Go HTTP service that handles user authentication using JWT tokens.

## Requirements

### POST /login
- Accept JSON body: `{"username": "...", "password": "..."}`
- Look up user in PostgreSQL database
- Verify bcrypt-hashed password
- Return signed JWT on success (HS256, 1-hour expiry)
- Return HTTP 401 on invalid credentials
- Return HTTP 429 after 5 failed attempts from the same IP within 60 seconds

### POST /refresh
- Accept a valid (non-expired) JWT in Authorization header
- Return a new JWT with a fresh 1-hour expiry
- Reject tokens older than 7 days regardless of expiry

### GET /me
- Require valid JWT in Authorization header
- Return the authenticated user's profile (id, username, email, created_at)

## Non-functional requirements
- JWT secret must be loaded from the `JWT_SECRET` environment variable — never hardcoded
- All database queries must use parameterized statements (no string interpolation)
- Passwords must never appear in logs or error responses
- Rate limiting state stored in Redis (key: `ratelimit:{ip}`, TTL: 60s)

## Implementation language
Go 1.22+. Use `net/http` standard library. JWT via `github.com/golang-jwt/jwt/v5`.
