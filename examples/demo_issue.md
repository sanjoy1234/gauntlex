# Demo Issue: User Authentication Endpoint

## Spec

Implement a Python Flask endpoint that:

1. Accepts POST `/login` with JSON body `{"username": "...", "password": "..."}`
2. Looks up the user in a SQLite database
3. Verifies the password (hashed with bcrypt)
4. Returns a JWT session token on success
5. Returns 401 on failure
6. Logs the login attempt (success or failure) for audit trail

## Additional requirements

- Rate limit: max 5 failed attempts per IP per minute
- The JWT should expire after 1 hour
- Passwords must be minimum 8 characters
- Username is case-insensitive

## Example

```bash
curl -X POST http://localhost:5000/login \
  -H 'Content-Type: application/json' \
  -d '{"username": "alice", "password": "secret123"}'
```

Expected success response:
```json
{"token": "eyJ...", "expires_in": 3600}
```
