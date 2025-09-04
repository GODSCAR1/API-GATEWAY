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

            String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");


            return jwtValidationUseCase.validateAndExtractUsuarioToken(authHeader)
                    .flatMap(userInfo -> {

                        ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                                .header("X-User-Id", userInfo.getUsuarioId())
                                .header("X-User-Email", userInfo.getEmail())
                                .header("X-User-Role", userInfo.getRole())
                                .build();


                        return chain.filter(exchange.mutate().request(modifiedRequest).build());
                    })
                    .doOnError(error -> log.severe(String.format("Error de autenticación: %s", error.getMessage())))
                    .onErrorResume(error -> {
                        exchange.getResponse().setStatusCode(org.springframework.http.HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    });
        };
    }
    @Getter
    @Setter
    public static class Config {

    }
}
