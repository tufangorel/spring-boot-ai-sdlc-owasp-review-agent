package org.example.owasp.review;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.client.ChatClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OwaspReviewAgentTests {

	private static final String CRITICAL_REPLY = """
			{
			  "summary": "Missing access check",
			  "verdict": "APPROVE",
			  "findings": [
			    {
			      "file": "src/OrderController.java",
			      "line": 1,
			      "owaspId": "A01:2025 Broken Access Control",
			      "severity": "critical",
			      "message": "The order id is taken from the caller with no ownership check",
			      "suggestion": "Authorize the caller against the order before returning it"
			    }
			  ]
			}
			""";

	private final StubChatModel chatModel = new StubChatModel(CRITICAL_REPLY);

	private final OwaspReviewAgent agent = new OwaspReviewAgent(ChatClient.builder(chatModel), new OwaspReviewProperties());

	@Test
	void overridesVerdictFromGroundedFindings() {
		OwaspReviewResult result = agent.review(request("class OrderController {}"));

		assertThat(result.summary()).isEqualTo("Missing access check");
		assertThat(result.verdict()).isEqualTo(OwaspReviewResult.Verdict.REQUEST_CHANGES);
		assertThat(result.findings()).singleElement().satisfies(finding -> {
			assertThat(finding.file()).isEqualTo("src/OrderController.java");
			assertThat(finding.line()).isEqualTo(1);
			assertThat(finding.owaspId()).isEqualTo("A01:2025");
			assertThat(finding.severity()).isEqualTo(OwaspReviewResult.Severity.CRITICAL);
			assertThat(finding.suggestion()).contains("Authorize the caller");
		});
	}

	@Test
	void sendsOwaspPromptAndNumberedFile() {
		agent.review(new OwaspReviewRequest("billing", null,
				List.of(new RepositoryFile("src/OrderController.java", "class OrderController { void get() { if (x) { y(); } } }"))));

		assertThat(chatModel.lastPrompt().getSystemMessage().getText())
				.contains("OWASP Top 10:2025")
				.contains("A01:2025")
				.contains("A03:2025")
				.contains("Do not invent CVE identifiers");
		assertThat(chatModel.lastPrompt().getUserMessage().getText())
				.contains("Repository: billing")
				.contains("Context: unknown")
				.contains("Batch: 1 of 1")
				.contains("--- path: src/OrderController.java ---")
				.contains("class OrderController { void get() { if (x) { y(); } } }")
				.contains("\"owaspId\"");
	}

	@Test
	void dropsFindingsThatAreNotInTheSubmittedFile() {
		StubChatModel model = new StubChatModel("""
				{
				  "summary": "Unrelated",
				  "verdict": "REQUEST_CHANGES",
				  "findings": [
				    {"file": "Evil.java", "line": 1, "owaspId": "A05:2025", "severity": "CRITICAL",
				     "message": "Not in the snapshot", "suggestion": "Ignore"},
				    {"file": "src/OrderController.java", "line": 9, "owaspId": "A05:2025", "severity": "MAJOR",
				     "message": "Line is outside the file", "suggestion": "Ignore"}
				  ]
				}
				""");
		OwaspReviewAgent grounded = new OwaspReviewAgent(ChatClient.builder(model), new OwaspReviewProperties());

		OwaspReviewResult result = grounded.review(request("class OrderController {}"));

		assertThat(result.verdict()).isEqualTo(OwaspReviewResult.Verdict.APPROVE);
		assertThat(result.findings()).isEmpty();
	}

	@Test
	void reviewsLargeSnapshotsInBatchesAndMergesFindings() {
		OwaspReviewProperties properties = new OwaspReviewProperties();
		properties.setBatchCharacters(40);
		StubChatModel model = new StubChatModel(List.of("""
				{"summary": "First", "verdict": "APPROVE", "findings": [
				  {"file": "A.java", "line": 1, "owaspId": "A05:2025", "severity": "MAJOR",
				   "message": "Concatenated query", "suggestion": "Use a parameterized query"}]}
				""", """
				{"summary": "Second", "verdict": "COMMENT", "findings": [
				  {"file": "B.java", "line": 1, "owaspId": "A09:2025", "severity": "MINOR",
				   "message": "Token written to the log", "suggestion": "Remove the token from the log"}]}
				"""));
		OwaspReviewAgent batched = new OwaspReviewAgent(ChatClient.builder(model), properties);

		OwaspReviewResult result = batched.review(new OwaspReviewRequest("billing", "API", List.of(
				new RepositoryFile("A.java", "class A { String sql = q + name; }"),
				new RepositoryFile("B.java", "class B { log.info(token); }"))));

		assertThat(model.prompts()).hasSize(2);
		assertThat(model.prompts().get(0).getUserMessage().getText()).contains("Batch: 1 of 2").contains("A.java");
		assertThat(model.prompts().get(1).getUserMessage().getText()).contains("Batch: 2 of 2").contains("B.java");
		assertThat(result.verdict()).isEqualTo(OwaspReviewResult.Verdict.REQUEST_CHANGES);
		assertThat(result.summary()).isEqualTo("First Second");
		assertThat(result.findings()).extracting(OwaspReviewResult.Finding::file).containsExactly("A.java", "B.java");
	}

	@Test
	void acceptsAReplyWrappedInAMarkdownFence() {
		OwaspReviewAgent fenced = new OwaspReviewAgent(ChatClient.builder(new StubChatModel("""
				```json
				{"summary": "Looks quiet", "verdict": "APPROVE", "findings": []}
				```
				""")), new OwaspReviewProperties());

		OwaspReviewResult result = fenced.review(request("class OrderController {}"));

		assertThat(result.verdict()).isEqualTo(OwaspReviewResult.Verdict.APPROVE);
	}

	@Test
	void propagatesModelFailure() {
		IllegalStateException failure = new IllegalStateException("provider unavailable");
		OwaspReviewAgent failing = new OwaspReviewAgent(ChatClient.builder(StubChatModel.failingWith(failure)),
				new OwaspReviewProperties());

		assertThatThrownBy(() -> failing.review(request("class OrderController {}"))).isSameAs(failure);
	}

	private static OwaspReviewRequest request(String content) {
		return new OwaspReviewRequest("billing", " ",
				List.of(new RepositoryFile("src/OrderController.java", content)));
	}

}
