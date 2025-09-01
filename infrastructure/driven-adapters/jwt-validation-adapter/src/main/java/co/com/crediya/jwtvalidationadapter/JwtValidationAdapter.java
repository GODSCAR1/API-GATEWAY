package co.com.crediya.jwtvalidationadapter;

import co.com.crediya.model.usuarioinfo.UsuarioInfo;
import co.com.crediya.model.usuarioinfo.gateways.JwtValidationGateway;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;

@Log
@Component
public class JwtValidationAdapter implements JwtValidationGateway {

    @Value("${jwt.secret}")
    private String jwtSecret;

    private SecretKey getSigningKey() {
        byte[] keyBytes = Base64.getDecoder().decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    @Override
    public Mono<UsuarioInfo> validateToken(String token) {
        return Mono.fromCallable(() -> {
            Claims claims = parseToken(token);

            return UsuarioInfo.builder()
                    .usuarioId(claims.getSubject())
                    .email(claims.get("email", String.class))
                    .role(claims.get("role", String.class))
                    .build();
        });
    }

    private Claims parseToken(String token) {

        SecretKey key = getSigningKey();
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        if(claims.getExpiration() != null && claims.getExpiration().before(new Date())) {
            throw new ExpiredJwtException(null, claims, "Token expirado");
        }
        log.info("Token parseado exitosamente");
        return claims;
    }
    @Override
    public Mono<Boolean> isValidToken(String token) {
        return this.validateToken(token)
                .map(usuarioInfo -> true)
                .onErrorReturn(false)
                .doOnSuccess(isValid -> log.info("La validacion del token resulto exitosa"));
    }
}
