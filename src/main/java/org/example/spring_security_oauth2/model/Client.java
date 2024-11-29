package org.example.spring_security_oauth2.model;


import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

import java.util.Set;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "clients")
@FieldDefaults(level = AccessLevel.PRIVATE)
public class Client {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long id;


    String password;

    @Email
    String email;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "client_roles", joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "role")
    Set<Role> roles;
}
