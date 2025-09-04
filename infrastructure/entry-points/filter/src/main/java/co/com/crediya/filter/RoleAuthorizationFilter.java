package co.com.crediya.filter;

import exception.RolAuthorizationException;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.java.Log;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

@Component
@Log
public class RoleAuthorizationFilter extends AbstractGatewayFilterFactory<RoleAuthorizationFilter.Config> {
    public RoleAuthorizationFilter() {
        super(Config.class);
    }
    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            log.info("Iniciando filtro de autorización por rol");
            // 1. Obtener rol del header (agregado por JwtAuthenticationFilter)
            String userRole = exchange.getRequest().getHeaders().getFirst("X-User-Role");

            // 2. Verificar si el rol está en la lista permitida
            if (!config.getAllowedRoles().contains(userRole)) {
                return Mono.error(new RolAuthorizationException("Rol no autorizado: " + userRole));
            }

            // 3. Continuar si el rol es válido
            return chain.filter(exchange);
        };
    }

    @Getter
    @Setter
    public static class Config {
        private List<String> allowedRoles = new ArrayList<>();

        // Constructor por defecto obligatorio
        public Config() {}

        // Constructor conveniente
        public Config(List<String> allowedRoles) {
            this.allowedRoles = allowedRoles != null ? allowedRoles : new ArrayList<>();
        }

        // Getter que siempre retorna lista válida
        public List<String> getAllowedRoles() {
            return allowedRoles != null ? allowedRoles : new ArrayList<>();
        }
    }
}
