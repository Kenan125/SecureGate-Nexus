package com.securegate.controller;

import com.securegate.model.Order;
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
@RequestMapping("/api/v1/orders")
@Slf4j
public class OrderController {

    private final Map<String, Order> orders = new ConcurrentHashMap<>();

    @GetMapping
    public ResponseEntity<List<Order>> getOrders(Authentication auth) {
        return ResponseEntity.ok(orders.values().stream()
                .filter(o -> o.getUserId().equals(auth.getName())).toList());
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getOrder(@PathVariable String id, Authentication auth) {
        Order o = orders.get(id);
        if (o == null) return ResponseEntity.notFound().build();
        if (!o.getUserId().equals(auth.getName()))
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "Not your order"));
        return ResponseEntity.ok(o);
    }

    @PostMapping
    public ResponseEntity<Order> createOrder(@RequestBody Order order, Authentication auth) {
        order.setOrderId(UUID.randomUUID().toString());
        order.setUserId(auth.getName());
        order.setStatus("CREATED");
        orders.put(order.getOrderId(), order);
        return ResponseEntity.status(HttpStatus.CREATED).body(order);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteOrder(@PathVariable String id, Authentication auth) {
        Order o = orders.get(id);
        if (o == null) return ResponseEntity.notFound().build();
        if (!o.getUserId().equals(auth.getName()))
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "Not your order"));
        orders.remove(id);
        return ResponseEntity.ok(Map.of("message", "Order deleted"));
    }
}
