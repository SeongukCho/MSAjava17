package kopo.poly.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * 로그아웃은 JWT 토큰을 쿠키에서 삭제하기 때문에
     * 로그아웃 처리를 위해 토큰 이름 가져오기
     */
    @Value("${jwt.token.access.name}")
    private String accessTokenName;

    @Value("${jwt.token.refresh.name}")
    private String refreshTokenName;

    /**
     * 로그인 및 회원가입에서 사용하는 해시 암호화
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        log.info(this.getClass().getName() + ".PasswordEncoder Start!");

        return new BCryptPasswordEncoder();
    }

    /**
     * SpringSecurity 의 인증 정보 관리 객체
     * SpringSecurity 에 저장된 인증정보 가져올 때 활용
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        log.info(this.getClass().getName() + ".filterChain Start!");

        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)  // CORS 사용 안함 처리하기
                .formLogin(login -> login               // 로그인 페이지 설정
                        .loginPage("/ss/login")
                        .loginProcessingUrl("/login/loginProc")
                        .usernameParameter("user_id")   // 로그인 id 로 사용할 html 의 input 객체의 name 값
                        .passwordParameter("password")  // 로그인 password 로 사용할 html 의 input 객체의 name 값

                        // 로그인 처리
                        .successForwardUrl("/login/loginSuccess")   // Web MVC, Controller 사용할 때 적용 / 로그인 성공 URL
                        .failureForwardUrl("/login/loginFail"))     // Web MVC, Controller 사용할 때 적용 / 로그인 실패 URL
                .logout(logout -> logout                // 로그아웃 페이지 설정
                        .logoutUrl("/user/logout")
                        .deleteCookies(accessTokenName, refreshTokenName)
                        .logoutSuccessUrl("/ss/login")) // 로그아웃이 성공하면, 로그인 화면으로 이동함

                // 세션 사용하지 않도록 설정함
                .sessionManagement(ss -> ss.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        log.info(this.getClass().getName() + ".filterChain End!");

        return http.build();
    }
}
