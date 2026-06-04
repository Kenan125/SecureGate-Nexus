package com.securegate.internal.controller;

import com.securegate.internal.model.Order;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/orders")
@Slf4j
public class OrderController {

    private final Map<String, Order> orderStore = new ConcurrentHashMap<>();

    @GetMapping
    public ResponseEntity<List<Order>> getOrders(Authentication auth) {
        String userId = auth.getName();
        List<Order> userOrders = orderStore.values().stream()
                .filter(o -> o.getUserId().equals(userId))
                .toList();
        log.debug("Orders fetched for userId={}, count={}", userId, userOrders.size());
        return ResponseEntity.ok(userOrders);
    }

    @GetMapping("/{orderId}")
    public ResponseEntity<?> getOrder(@PathVariable String orderId, Authentication auth) {
        Order order = orderStore.get(orderId);
        if (order == null) {
            return ResponseEntity.notFound().build();
        }
        if (!order.getUserId().equals(auth.getName())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Access denied: not your order"));
        }
        return ResponseEntity.ok(order);
    }

    @PostMapping
    public ResponseEntity<Order> createOrder(@RequestBody Order order, Authentication auth) {
        order.setOrderId(UUID.randomUUID().toString());
        order.setUserId(auth.getName());
        order.setStatus("CREATED");
        orderStore.put(order.getOrderId(), order);
        log.info("Order created: orderId={}, userId={}", order.getOrderId(), auth.getName());
        return ResponseEntity.status(HttpStatus.CREATED).body(order);
    }

    @DeleteMapping("/{orderId}")
    public ResponseEntity<?> deleteOrder(@PathVariable String orderId, Authentication auth) {
        Order order = orderStore.get(orderId);
        if (order == null) {
            return ResponseEntity.notFound().build();
        }
        if (!order.getUserId().equals(auth.getName())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Access denied: not your order"));
        }
        orderStore.remove(orderId);
        log.info("Order deleted: orderId={}, userId={}", orderId, auth.getName());
        return ResponseEntity.ok(Map.of("message", "Order deleted"));
    }
}
