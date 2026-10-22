package org.example.owasp.review;

import java.util.List;
import java.util.Locale;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record OwaspReviewResult(
		String summary,
		Verdict verdict,
		List<Finding> findings) {

	public enum Verdict {
		APPROVE, COMMENT, REQUEST_CHANGES;

		@JsonCreator
		static Verdict fromJson(String value) {
			if (value == null || value.isBlank()) {
				return null;
			}
			return Verdict.valueOf(value.trim().toUpperCase(Locale.ROOT));
		}
	}

	public enum Severity {
		INFO, MINOR, MAJOR, CRITICAL;

		@JsonCreator
		static Severity fromJson(String value) {
			if (value == null || value.isBlank()) {
				return null;
			}
			return Severity.valueOf(value.trim().toUpperCase(Locale.ROOT));
		}
	}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record Finding(
			String file,
			Integer line,
			String owaspId,
			Severity severity,
			String message,
			String suggestion) {
	}

}
