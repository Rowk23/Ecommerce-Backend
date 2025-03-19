package com.example.shop.repositories;

import com.example.shop.models.Product;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProductRepository extends JpaRepository<Product,Integer> {
}
