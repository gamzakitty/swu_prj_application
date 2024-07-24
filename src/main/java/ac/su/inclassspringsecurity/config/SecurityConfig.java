@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final TokenProvider tokenProvider;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(
                (authorizeHttpRequests) ->
                    authorizeHttpRequests
                        .requestMatchers("/users/login", "/csrf-token", "/products-temp/**").permitAll()
                        .requestMatchers("/products-temp/**").hasAnyRole("SUPER_ADMIN", "ADMIN")
                        .anyRequest().authenticated()
            )
            .csrf(
                (csrf) -> csrf
                    .ignoringRequestMatchers(
                        new AntPathRequestMatcher("/api/**"),
                        new AntPathRequestMatcher("/users/login")
                    )
            )
            .headers(
                (headers) ->
                    headers.addHeaderWriter(
                        new XFrameOptionsHeaderWriter(
                            XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN
                        )
                    )
            )
            .formLogin(
                (formLogin) ->
                    formLogin
                        .loginPage("/users/login")
                        .defaultSuccessUrl("/")
            )
            .logout(
                (logout) ->
                    logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/users/logout"))
                        .logoutSuccessUrl("/")
                        .invalidateHttpSession(true)
            )
            .sessionManagement(
                (sessionConfig) ->
                    sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .addFilterBefore(
                tokenAuthenticationFilter(),
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
