package com.tailtales.backend.error.handler;

import com.tailtales.backend.error.dto.ErrorDto;
import com.tailtales.backend.error.enumType.ErrorCode;
import com.tailtales.backend.error.exception.CustomException;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;

import java.util.HashMap;
import java.util.Map;

@Log4j2
@RestControllerAdvice
public class CustomExceptionHandler {

    @ExceptionHandler(CustomException.class)
    public ResponseEntity<ErrorDto> handleCustomException(CustomException e) {
        ErrorCode errorCode = e.getErrorCode();
        log.warn("CustomException 발생: code={}, message={}", errorCode.getCode(), errorCode.getMessage());

        ErrorDto errorDto = ErrorDto.builder()
                .code(errorCode.getCode())
                .message(errorCode.getMessage())
                .build();

        return new ResponseEntity<>(errorDto, errorCode.getStatus());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorDto> handleMethodArgumentNotValidException(MethodArgumentNotValidException e) {

        String defaultMessage = e.getBindingResult().getFieldError() != null ?
                e.getBindingResult().getFieldError().getDefaultMessage() : ErrorCode.INVALID_INPUT_VALUE.getMessage(); // ⭐️ 기본 메시지도 ErrorCode에서 가져오는 것을 고려

        Map<String, String> errors = new HashMap<>();
        e.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });
        log.warn("유효성 검사 실패: {}", errors);

        ErrorDto errorDto = ErrorDto.builder()
                .code(ErrorCode.INVALID_INPUT_VALUE.getCode())
                .message(defaultMessage)
                .build();

        return new ResponseEntity<>(errorDto, ErrorCode.INVALID_INPUT_VALUE.getStatus());
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<ErrorDto> handleNoHandlerFoundException(NoHandlerFoundException e) {
        log.warn("핸들러를 찾을 수 없습니다: Request URL = {}, Http Method = {}", e.getRequestURL(), e.getHttpMethod());

        ErrorDto errorDto = ErrorDto.builder()
                .code("404_NOT_FOUND") // 적절한 ErrorCode 추가 고려 (P006 POST_NOT_FOUND 등과 구별)
                .message("요청하신 리소스를 찾을 수 없습니다.")
                .build();

        return new ResponseEntity<>(errorDto, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorDto> handleGeneralException(Exception e) {
        log.error("알 수 없는 서버 내부 예외가 발생했습니다.", e); // 스택 트레이스와 함께 에러 레벨로 로그 기록

        ErrorDto errorDto = ErrorDto.builder()
                .code(ErrorCode.INTERNAL_SERVER_ERROR.getCode())
                .message(ErrorCode.INTERNAL_SERVER_ERROR.getMessage())
                .build();

        return new ResponseEntity<>(errorDto, ErrorCode.INTERNAL_SERVER_ERROR.getStatus());
    }
}
