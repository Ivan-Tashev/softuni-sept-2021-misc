package bg.softuni.mobilelele.user;

import bg.softuni.mobilelele.model.entity.UserEntity;
import bg.softuni.mobilelele.repository.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class MobileleleUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    public MobileleleUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity userEntity = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Username: " + username + " - not found! No such User."));

        List<GrantedAuthority> authorities = userEntity.getRoles().stream()
                .map(userRoleEntity -> new SimpleGrantedAuthority("ROLE_" + userRoleEntity.getRole().name()))
                .collect(Collectors.toList());
        // return User(org.springframework.security)
        return new User(userEntity.getUsername(), userEntity.getPassword(), authorities);
    }
}
