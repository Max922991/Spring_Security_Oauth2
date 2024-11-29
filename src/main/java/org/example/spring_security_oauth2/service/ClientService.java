package org.example.spring_security_oauth2.service;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.example.spring_security_oauth2.model.Client;
import org.example.spring_security_oauth2.repository.ClientRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ClientService implements UserDetailsService {

    private final ClientRepository clientRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Client client = clientRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException("Client not found"));

        return new User(
                client.getEmail(),
                client.getPassword(),
                client.getRoles().stream()
                        .map(role -> new SimpleGrantedAuthority(role.getAuthority()))
                        .toList()
        );
    }
}
