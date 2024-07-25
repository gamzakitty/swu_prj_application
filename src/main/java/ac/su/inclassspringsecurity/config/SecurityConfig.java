package ac.su.inclassspringsecurity.config;

import ac.su.inclassspringsecurity.config.jwt.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final TokenProvider tokenProvider;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorizeRequests ->
                authorizeRequests
                    .requestMatchers("/public/**").permitAll() // /public 경로는 인증 없이 접근 가능
                    .anyRequest().authenticated() // 그 외의 모든 경로는 인증 필요
            )
            .formLogin(formLogin ->
                formLogin
                    .loginPage("/users/login")
                    .permitAll()
            )
            .logout(logout ->
                logout
                    .logoutRequestMatcher(new AntPathRequestMatcher("/users/logout"))
                    .logoutSuccessUrl("/")
                    .invalidateHttpSession(true)
            )
            .csrf(csrf ->
                csrf
                    .ignoringRequestMatchers(
                        new AntPathRequestMatcher("/api/**"),
                        new AntPathRequestMatcher("/users/login")
                    )
                    // .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())  // 필요 시 추가
            )
            .headers(headers ->
                headers.addHeaderWriter(
                    new XFrameOptionsHeaderWriter(
                        XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN
                    )
                )
            )
            .sessionManagement(sessionManagement ->
                sessionManagement
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .addFilterBefore(
                tokenAuthenticationFilter(), // 토큰을 username, password 검사보다 먼저 검사한다.
                UsernamePasswordAuthenticationFilter.class
            );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter(tokenProvider);
    }
}
