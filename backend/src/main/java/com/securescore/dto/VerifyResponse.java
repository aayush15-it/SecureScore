package com.securescore.dto;

import java.util.List;

public record VerifyResponse(
    String checkName,
    String target,
    List<FindingResponse> before,
    List<FindingResponse> after,
    boolean improved
) {}
