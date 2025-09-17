package co.com.crediya.jwtvalidationadapter.message;

public enum JwtValidationMessage {

    TOKEN_PARSEADO_EXITOSO("Token parseado exitosamente");

    private final String mensaje;

    JwtValidationMessage(String mensaje) {
        this.mensaje = mensaje;
    }

    public String getMensaje() {
        return mensaje;
    }
}
