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
                .antMatchers("/public/**").permitAll() // /public 경로는 인증 없이 접근 가능
                .anyRequest().authenticated() // 그 외의 모든 경로는 인증 필요
                .and()
            .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
            .logout()
                .permitAll();
            )

//            .csrf(csrf -> csrf
//                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//            )
            .csrf(
    (csrf) -> csrf
        .ignoringRequestMatchers(
            new AntPathRequestMatcher("/api/**"),
            new AntPathRequestMatcher("/users/login")
        )
)

//                (csrf) ->
//                    csrf.ignoringRequestMatchers(
//                        // 필요 시 특정 페이지 CSRF 토큰 무시 설정
//                        new AntPathRequestMatcher("/h2-console/**")
//                        // , new AntPathRequestMatcher("/login")
//                        // , new AntPathRequestMatcher("/logout")
//                        // , new AntPathRequestMatcher("/signup")
//                    )
//            )
            .headers(
                (headers) ->
                    headers.addHeaderWriter(
                        new XFrameOptionsHeaderWriter(
                            // X-Frame-Options 는 웹 페이지 내에서 다른 웹 페이지 표시 허용 여부 제어
                            XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN  // 동일 도메인 내에서 표시 허용
                        )
                    )
            )
            .formLogin(
                (formLogin) ->
                    formLogin  // Controller 에 PostMapping URL 바인딩이 없어도
                               // POST 요청을 아래 라인에서 수신하고 인증 처리
                        .loginPage("/users/login")
                        .defaultSuccessUrl("/")
//                AbstractHttpConfigurer::disable
            )
            .logout(
                (logout) ->
                    logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/users/logout"))
                        .logoutSuccessUrl("/")
                        .invalidateHttpSession(true)
            )
            .sessionManagement(
                (sessionConfig) -> {
                    sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                }
            )
            .addFilterBefore(
                tokenAuthenticationFilter(),  // 토큰을 username, password 검사보다 먼저 검사한다.
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
