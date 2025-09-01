package co.com.crediya.model.usuarioinfo.gateways;

import co.com.crediya.model.usuarioinfo.UsuarioInfo;
import reactor.core.publisher.Mono;

public interface JwtValidationGateway {
    Mono<UsuarioInfo> validateToken(String token);
    Mono<Boolean> isValidToken(String token);
}
