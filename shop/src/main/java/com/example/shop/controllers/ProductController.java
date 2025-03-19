package com.example.shop.controllers;

import com.example.shop.models.Product;
import com.example.shop.services.ProductService;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;

import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
@CrossOrigin(origins = "http://localhost:4200")
public class ProductController {
    private final ProductService productService;

    @GetMapping("/home")
    public List<Product> all(){
        return productService.getAll();
    }

    @GetMapping("/{id}")
    public Optional<Product> one(@PathVariable int id) {
        return productService.getOne(id);
    }

    @DeleteMapping("/delete/{id}")
    public void del(@PathVariable int id) {
        productService.deleteOne(id);
    }

    
}
