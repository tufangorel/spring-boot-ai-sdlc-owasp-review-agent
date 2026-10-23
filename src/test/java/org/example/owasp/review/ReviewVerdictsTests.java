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
	void usesADefaultSummaryWhenNoneIsGiven() {
		assertThat(ReviewVerdicts.decide(null, List.of(finding(OwaspReviewResult.Severity.MINOR))).summary())
				.isEqualTo("Review completed.");
		assertThat(ReviewVerdicts.decide("  ", List.of(finding(OwaspReviewResult.Severity.MINOR))).summary())
				.isEqualTo("Review completed.");
		assertThat(ReviewVerdicts.decide("  Notes  ", List.of(finding(OwaspReviewResult.Severity.MINOR))).summary())
				.isEqualTo("Notes");
	}

	@Test
	void readsVerdictAndSeverityCaseInsensitivelyAndTreatsBlankAsMissing() {
		assertThat(OwaspReviewResult.Verdict.fromJson(" request_changes "))
				.isEqualTo(OwaspReviewResult.Verdict.REQUEST_CHANGES);
		assertThat(OwaspReviewResult.Verdict.fromJson(null)).isNull();
		assertThat(OwaspReviewResult.Verdict.fromJson(" ")).isNull();
		assertThat(OwaspReviewResult.Severity.fromJson(" major ")).isEqualTo(OwaspReviewResult.Severity.MAJOR);
		assertThat(OwaspReviewResult.Severity.fromJson(null)).isNull();
		assertThat(OwaspReviewResult.Severity.fromJson(" ")).isNull();
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
