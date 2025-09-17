package co.com.crediya.usecase.jwtvalidation;

import co.com.crediya.model.usuarioinfo.UsuarioInfo;
import co.com.crediya.model.usuarioinfo.gateways.JwtValidationGateway;
import co.com.crediya.usecase.jwtvalidation.exception.InvalidHeaderException;
import co.com.crediya.usecase.jwtvalidation.message.JwtMessage;
import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@RequiredArgsConstructor
public class JwtValidationUseCase {

    private final JwtValidationGateway jwtValidationGateway;

    public Mono<UsuarioInfo> validateAndExtractUsuarioToken(String authHeader) {
        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
            return Mono.error(new InvalidHeaderException(JwtMessage.HEADER_INVALIDO.getMensaje()));
        }

        String token = authHeader.substring(7);
        return jwtValidationGateway.validateToken(token);
    }

}
