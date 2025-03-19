package com.example.shop.services;

import com.example.shop.models.Product;
import com.example.shop.repositories.ProductRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class ProductService {
    private final ProductRepository productRepository;

    public List<Product> getAll(){
        return productRepository.findAll();
    }

    public Optional<Product> getOne(int id) {
        return productRepository.findById(id);
    }

    public void deleteOne(int id) {
        productRepository.deleteById(id);
    }
}
