package org.example.owasp.review;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RepositorySubmissionTests {

	private final RepositorySubmission submission = new RepositorySubmission(new OwaspReviewProperties());

	@Test
	void normalizesPathsAndKeepsContext() {
		OwaspReviewRequest prepared = submission.prepare(new OwaspReviewRequest(" billing ", "Orders API",
				List.of(new RepositoryFile("src\\OrderController.java", "class OrderController {}"))));

		assertThat(prepared.repositoryName()).isEqualTo("billing");
		assertThat(prepared.context()).isEqualTo("Orders API");
		assertThat(prepared.files()).containsExactly(new RepositoryFile("src/OrderController.java", "class OrderController {}"));
	}

	@Test
	void rejectsPathTraversalDuplicateAndAbsolutePaths() {
		assertThatThrownBy(() -> submission.prepare(request("../secret.java")))
				.isInstanceOf(ResponseStatusException.class)
				.extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
				.isEqualTo(HttpStatus.BAD_REQUEST);

		assertThatThrownBy(() -> submission.prepare(request("C:/secret.java")))
				.isInstanceOf(ResponseStatusException.class);

		assertThatThrownBy(() -> submission.prepare(new OwaspReviewRequest("billing", null, List.of(
				new RepositoryFile("src/A.java", "class A {}"),
				new RepositoryFile("src\\A.java", "class A {}")))))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("Duplicate file path");
	}

	@Test
	void rejectsTooManyFiles() {
		OwaspReviewProperties properties = new OwaspReviewProperties();
		properties.setMaxFiles(1);
		RepositorySubmission limited = new RepositorySubmission(properties);

		assertThatThrownBy(() -> limited.prepare(new OwaspReviewRequest("billing", null, List.of(
				new RepositoryFile("A.java", "class A {}"),
				new RepositoryFile("B.java", "class B {}")))))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("more than 1 files");
	}

	@Test
	void rejectsAMissingRepositoryName() {
		List<RepositoryFile> files = List.of(new RepositoryFile("A.java", "class A {}"));

		assertThatThrownBy(() -> submission.prepare(new OwaspReviewRequest(null, null, files)))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("Repository name is required");
		assertThatThrownBy(() -> submission.prepare(new OwaspReviewRequest("  ", null, files)))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("Repository name is required");
	}

	@Test
	void rejectsMissingFiles() {
		assertThatThrownBy(() -> submission.prepare(new OwaspReviewRequest("billing", null, null)))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("At least one file is required");
		assertThatThrownBy(() -> submission.prepare(new OwaspReviewRequest("billing", null, List.of())))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("At least one file is required");
	}

	@Test
	void rejectsEmptyFiles() {
		assertThatThrownBy(() -> submission.prepare(new OwaspReviewRequest("billing", null,
				List.of(new RepositoryFile("A.java", null)))))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("File is empty: A.java");
		assertThatThrownBy(() -> submission.prepare(new OwaspReviewRequest("billing", null,
				List.of(new RepositoryFile("A.java", "  ")))))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("File is empty: A.java");
	}

	@Test
	void rejectsAFileOrRepositoryOverTheSizeLimits() {
		OwaspReviewProperties properties = new OwaspReviewProperties();
		properties.setMaxFileCharacters(12);
		properties.setMaxTotalCharacters(15);
		RepositorySubmission limited = new RepositorySubmission(properties);

		assertThatThrownBy(() -> limited.prepare(new OwaspReviewRequest("billing", null,
				List.of(new RepositoryFile("A.java", "class A { int x; }")))))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("File exceeds the maximum review size: A.java");
		assertThatThrownBy(() -> limited.prepare(new OwaspReviewRequest("billing", null, List.of(
				new RepositoryFile("A.java", "class A {}"),
				new RepositoryFile("B.java", "class B {}")))))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("Repository exceeds the maximum review size");
	}

	private static OwaspReviewRequest request(String path) {
		return new OwaspReviewRequest("billing", null, List.of(new RepositoryFile(path, "class A {}")));
	}

}
