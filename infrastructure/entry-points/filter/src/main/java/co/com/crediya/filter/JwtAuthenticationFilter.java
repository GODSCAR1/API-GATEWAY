package co.com.crediya.filter;

import co.com.crediya.usecase.jwtvalidation.JwtValidationUseCase;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.java.Log;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

@Component
@Log
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    private final JwtValidationUseCase jwtValidationUseCase;

    public JwtAuthenticationFilter(JwtValidationUseCase jwtValidationUseCase) {
        super(Config.class);
        this.jwtValidationUseCase = jwtValidationUseCase;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            log.info("Iniciando filtro de autenticación");
            // 1. Obtener token del header Authorization
            String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");

            // 2. Validar JWT
            return jwtValidationUseCase.validateAndExtractUsuarioToken(authHeader)
                    .flatMap(userInfo -> {
                        // 3. Agregar headers con info del usuario
                        ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                                .header("X-User-Id", userInfo.getUsuarioId())
                                .header("X-User-Email", userInfo.getEmail())
                                .header("X-User-Role", userInfo.getRole())
                                .build();

                        // 4. Continuar hacia el microservicio
                        return chain.filter(exchange.mutate().request(modifiedRequest).build());
                    })
                    .doOnError(error -> log.severe(String.format("Error de autenticación: %s", error.getMessage())));
        };
    }
    @Getter
    @Setter
    public static class Config {

    }
}
