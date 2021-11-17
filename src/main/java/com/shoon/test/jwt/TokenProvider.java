package com.shoon.test.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
@Component
public class TokenProvider implements InitializingBean {
    private static final String AUTHORITIES_KEY = "auth";

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.token-validity-in-seconds}")
    private long tokenValidityInMilliseconds;

    private Key key;

    @Override
    public void afterPropertiesSet() throws Exception {
        // 빈 초기화 시 코드 구현
        // @PostConstruct 어노테이션 비슷하며 해당 어노테이션이후에 위의 어노테이션이 실행되며
        // javax 의 어노테이션이다.
//        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(secret);

        byte[] keyBytes = Decoders.BASE64.decode(secret);
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS512;
        this.key = new SecretKeySpec(keyBytes, signatureAlgorithm.getJcaName());
//        Keys.hmacShaKeyFor(keyBytes);
    }

    // 토큰 생성
    public String createToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        Long now = new Date().getTime();
        // 현재시간 + 만료시간
        Date Validity = new Date(now + this.tokenValidityInMilliseconds * 1000);

        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(SignatureAlgorithm.HS512, key)
                .setExpiration(Validity)
                .compact();
    }

    // 권한 정보를 파싱하여 Authentication 객체 리턴
    public Authentication getAuthentication(String token){
        Claims claims = Jwts
                .parser()
                .setSigningKey(key)
                .parseClaimsJws(token)
                .getBody();

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    // 토큰 검증
    public boolean validateToken(String token){
        try {
            Jwts.parser().setSigningKey(key).parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            e.printStackTrace();
        } catch (UnsupportedJwtException e) {
            log.info("잘못된 Jwt 서명입니다.");
        } catch (MalformedJwtException e) {
            log.info("만료된 Jwt 토큰입니다.");
        } catch (SignatureException e) {
            log.info("지원되지 않는 Jwt 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.info("Jwt 토큰이 잘못되었습니다.");
        }
        return false;
    }
}
