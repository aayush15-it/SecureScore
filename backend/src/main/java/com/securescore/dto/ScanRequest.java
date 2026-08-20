package com.securescore.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ScanRequest(
    @NotBlank(message = "URL is required")
    @Size(max = 2048, message = "URL must be 2048 characters or less")
    String url
) {}
