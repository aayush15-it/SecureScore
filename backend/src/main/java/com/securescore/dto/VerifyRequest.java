package com.securescore.dto;

import jakarta.validation.constraints.NotBlank;

public record VerifyRequest(
    @NotBlank(message = "checkName is required")
    String checkName
) {}
