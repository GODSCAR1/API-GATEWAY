package co.com.crediya.usecase.jwtvalidation.exception;

public class InvalidHeaderException extends RuntimeException {
    public InvalidHeaderException(String message) {
        super(message);
    }
}
