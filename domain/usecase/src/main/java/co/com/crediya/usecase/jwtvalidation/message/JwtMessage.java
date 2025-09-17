package co.com.crediya.usecase.jwtvalidation.message;

public enum JwtMessage {

    HEADER_INVALIDO("Header de autorizacion invalido");

    private final String mensaje;

    JwtMessage(String mensaje) {
        this.mensaje = mensaje;
    }

    public String getMensaje() {
        return mensaje;
    }
}
