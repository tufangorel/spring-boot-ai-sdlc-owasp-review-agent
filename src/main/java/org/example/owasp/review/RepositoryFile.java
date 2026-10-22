package org.example.owasp.review;

import jakarta.validation.constraints.NotBlank;

public record RepositoryFile(
		@NotBlank String path,
		@NotBlank String content) {
}
