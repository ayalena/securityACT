package com.example.securityACT.customer;

import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/customers")
public class CustomerManagementController {

    private static final List<Customer> CUSTOMERS = Arrays.asList(
            new Customer(1, "Fenn Lazarus"),
            new Customer(2, "Eline Hermans"),
            new Customer(3, "Charles Xavier")
    );

    @GetMapping
    public List<Customer> getAllCustomers() {
        System.out.println("getAllCustomers");
        return CUSTOMERS;
    }

    @PostMapping
    public void registerNewCustomer(@RequestBody Customer customer) {
        System.out.println("registerNewCustomer");
        System.out.println(customer);
    }

    @DeleteMapping(path = "{customerId}")
    public void deleteCustomer(@PathVariable("customerId") Integer customerId) {
        System.out.println("deleteCustomer");
        System.out.println(customerId);
    }

    @PutMapping(path = "{customerId}")
    public void updateCustomer(@PathVariable("customerId")Integer customerId, @RequestBody Customer customer) {
        System.out.println("updateCustomer");
        System.out.println(String.format("%s %s", customerId, customer));
    }

}
