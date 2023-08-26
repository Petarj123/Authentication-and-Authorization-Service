package com.auth.app.auth.DTO;

import lombok.Builder;

@Builder
public record LoginResponse(String token) {
}
