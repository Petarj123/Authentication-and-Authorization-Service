package com.auth.app.auth.DTO;

import lombok.Builder;

@Builder
public record ExceptionResponse(String exception, String message, int code) {
}
