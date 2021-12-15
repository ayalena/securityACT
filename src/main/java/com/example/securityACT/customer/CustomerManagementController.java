package com.example.securityACT.customer;

import org.springframework.security.access.prepost.PreAuthorize;
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

//    hasRole("ROLE_")
//    hasAnyRole("ROLE_")
//    hasAuthority("permission")
//    hasAnyAuthority("permission")

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
    public List<Customer> getAllCustomers() {
        System.out.println("getAllCustomers");
        return CUSTOMERS;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('customer:write')")
    public void registerNewCustomer(@RequestBody Customer customer) {
        System.out.println("registerNewCustomer");
        System.out.println(customer);
    }

    @DeleteMapping(path = "{customerId}")
    @PreAuthorize("hasAuthority('customer:write')")
    public void deleteCustomer(@PathVariable("customerId") Integer customerId) {
        System.out.println("deleteCustomer");
        System.out.println(customerId);
    }

    @PutMapping(path = "{customerId}")
    @PreAuthorize("hasAuthority('customer:write')")
    public void updateCustomer(@PathVariable("customerId")Integer customerId, @RequestBody Customer customer) {
        System.out.println("updateCustomer");
        System.out.println(String.format("%s %s", customerId, customer));
    }

}
