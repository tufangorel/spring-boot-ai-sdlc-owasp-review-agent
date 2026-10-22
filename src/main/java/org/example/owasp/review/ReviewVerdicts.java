package org.example.owasp.review;

import java.util.List;

import org.example.owasp.review.OwaspReviewResult.Finding;
import org.example.owasp.review.OwaspReviewResult.Severity;
import org.example.owasp.review.OwaspReviewResult.Verdict;

final class ReviewVerdicts {

	private ReviewVerdicts() {
	}

	static OwaspReviewResult decide(String summary, List<Finding> findings) {
		boolean blocking = findings.stream()
				.anyMatch(finding -> finding.severity() == Severity.MAJOR || finding.severity() == Severity.CRITICAL);
		boolean notes = findings.stream()
				.anyMatch(finding -> finding.severity() == Severity.MINOR || finding.severity() == Severity.INFO);
		Verdict verdict = blocking ? Verdict.REQUEST_CHANGES : notes ? Verdict.COMMENT : Verdict.APPROVE;
		String text = summary == null || summary.isBlank() ? "Review completed." : summary.trim();
		if (findings.isEmpty()) {
			text = "No OWASP Top 10:2025 findings grounded in the submitted files.";
			verdict = Verdict.APPROVE;
		}
		return new OwaspReviewResult(text, verdict, List.copyOf(findings));
	}

}
