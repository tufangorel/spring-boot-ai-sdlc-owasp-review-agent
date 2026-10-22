package org.example.owasp.review;

import java.util.List;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ReviewVerdictsTests {

	@Test
	void requestsChangesForMajorOrCritical() {
		OwaspReviewResult result = ReviewVerdicts.decide("Issues found", List.of(
				finding(OwaspReviewResult.Severity.MAJOR),
				finding(OwaspReviewResult.Severity.CRITICAL)));

		assertThat(result.verdict()).isEqualTo(OwaspReviewResult.Verdict.REQUEST_CHANGES);
		assertThat(result.summary()).isEqualTo("Issues found");
	}

	@Test
	void commentsForMinorOrInfoOnly() {
		OwaspReviewResult result = ReviewVerdicts.decide("Notes", List.of(finding(OwaspReviewResult.Severity.INFO)));

		assertThat(result.verdict()).isEqualTo(OwaspReviewResult.Verdict.COMMENT);
	}

	@Test
	void approvesWhenNothingIsGrounded() {
		OwaspReviewResult result = ReviewVerdicts.decide("The model claimed an issue", List.of());

		assertThat(result.verdict()).isEqualTo(OwaspReviewResult.Verdict.APPROVE);
		assertThat(result.summary()).isEqualTo("No OWASP Top 10:2025 findings grounded in the submitted files.");
		assertThat(result.findings()).isEmpty();
	}

	private static OwaspReviewResult.Finding finding(OwaspReviewResult.Severity severity) {
		return new OwaspReviewResult.Finding("A.java", 1, "A01:2025", severity, "Missing check", "Authorize the caller");
	}

}
