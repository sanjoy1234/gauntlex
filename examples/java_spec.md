# Spec: Order Management Service (Java / Spring Boot)

## Overview

Implement a Spring Boot REST service for managing customer orders in an e-commerce platform.

## Requirements

### POST /orders
- Accept JSON: `{"items": [{"product_id": "...", "quantity": int}], "shipping_address": {...}}`
- Validate each product_id exists in the product catalog (call internal ProductService)
- Reserve inventory via InventoryService (throw `InsufficientStockException` if unavailable)
- Persist the order with status `PENDING` in MySQL
- Publish an `OrderCreatedEvent` to Kafka topic `orders.created`
- Return HTTP 201 with the created order (include `order_id`, `total_price`, `status`)

### GET /orders/{orderId}
- Return the order detail for the given ID
- Enforce ownership: only the authenticated user or `ROLE_ADMIN` may view an order
- Return HTTP 404 if not found, HTTP 403 if access denied

### PATCH /orders/{orderId}/cancel
- Allow cancellation only if order status is `PENDING` or `PROCESSING`
- Update status to `CANCELLED`, release inventory reservation
- Publish `OrderCancelledEvent` to Kafka topic `orders.cancelled`
- Return HTTP 409 if order cannot be cancelled (already shipped)

## Security requirements
- Authentication via Spring Security + JWT; extract `user_id` from token claims
- All database access through JPA repositories with parameterized queries
- No business logic in controllers — delegate to `OrderService`
- Sensitive fields (payment info, full address) excluded from logs

## Implementation language
Java 21, Spring Boot 3.x, Spring Security 6, Spring Data JPA, Apache Kafka client.
