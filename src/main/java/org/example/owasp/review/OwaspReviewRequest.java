package org.example.owasp.review;

import java.util.List;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

public record OwaspReviewRequest(
		@NotBlank String repositoryName,
		String context,
		@NotEmpty List<@Valid RepositoryFile> files) {
}
