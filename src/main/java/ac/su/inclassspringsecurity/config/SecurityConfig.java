package ac.su.inclassspringsecurity.config;

import ac.su.inclassspringsecurity.config.jwt.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity  // URL 요청에 대한 Spring Security 동작 활성화
@RequiredArgsConstructor
public class SecurityConfig {
    private final TokenProvider tokenProvider;

    @Bean
SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
            .antMatchers("/public/**").permitAll() // 인증 없이 접근 가능한 경로
            .anyRequest().authenticated() // 나머지 요청은 인증 필요
            .and()
        .formLogin()
            .loginPage("/login")
            .permitAll()
            .and()
        .logout()
            .permitAll()
            .and()
        .csrf(csrf -> csrf
            .ignoringRequestMatchers(
                new AntPathRequestMatcher("/api/**"),
                new AntPathRequestMatcher("/users/login"),
                new AntPathRequestMatcher("/signup"),
                new AntPathRequestMatcher("/products")
            )
        )
        .headers(headers -> headers
            .addHeaderWriter(new XFrameOptionsHeaderWriter(
                XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN
            ))
        )
        .sessionManagement(sessionConfig -> 
            sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        )
        .addFilterBefore(
            tokenAuthenticationFilter(), 
            UsernamePasswordAuthenticationFilter.class
        )
        ;
        return http.build();
    }

    // passwordEncoder 빈 등록
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter(tokenProvider);
    }
}
