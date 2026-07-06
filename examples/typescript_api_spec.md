# Spec: Payment Processing API (TypeScript / Node.js)

## Overview

Implement a TypeScript Express service that processes payment intents and stores
transaction records.

## Requirements

### POST /payments/intent
- Accept JSON: `{"amount": number, "currency": "usd"|"eur", "user_id": string}`
- Validate amount is a positive integer (cents), max $10,000
- Create a Stripe PaymentIntent via the Stripe SDK
- Store intent record in PostgreSQL with status `pending`
- Return `{ "client_secret": "...", "intent_id": "..." }`
- Require Bearer token authentication (validate against users table)

### POST /payments/webhook
- Receive Stripe webhook events (signature verified via `stripe.webhooks.constructEvent`)
- On `payment_intent.succeeded`: update record status to `completed`
- On `payment_intent.payment_failed`: update record status to `failed`, increment `failure_count`
- Return HTTP 200 immediately (async DB update acceptable)

### GET /payments/:id
- Return the payment record for the given intent ID
- Only the owning user may access their own payment records
- Reject with HTTP 403 if the authenticated user doesn't own the record

## Security requirements
- Stripe secret key loaded from `STRIPE_SECRET_KEY` env var
- Webhook secret from `STRIPE_WEBHOOK_SECRET` env var
- All SQL via parameterized queries — no string concatenation
- `user_id` from JWT payload, never from request body (prevents IDOR)
- Log transaction IDs only — never log card numbers, amounts, or PII

## Implementation language
TypeScript 5.x, Node.js 20+. Framework: Express 4. ORM: Prisma.
