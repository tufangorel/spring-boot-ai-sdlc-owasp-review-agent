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
	void dropsMalformedFindingsAndTrimsTheOnesItKeeps() {
		OwaspReviewAgent strict = new OwaspReviewAgent(ChatClient.builder(new StubChatModel("""
				{"summary": "Mixed", "verdict": "REQUEST_CHANGES", "findings": [
				  null,
				  {"line": 1, "owaspId": "A05:2025", "severity": "MAJOR", "message": "No file", "suggestion": "Fix"},
				  {"file": "src/OrderController.java", "line": 1, "owaspId": "A05:2025",
				   "message": "No severity", "suggestion": "Fix"},
				  {"file": "src/OrderController.java", "line": 1, "owaspId": "A05:2025", "severity": " ",
				   "message": "Blank severity", "suggestion": "Fix"},
				  {"file": "src/OrderController.java", "line": 1, "owaspId": "A05:2025", "severity": "MAJOR",
				   "suggestion": "Fix"},
				  {"file": "src/OrderController.java", "line": 1, "owaspId": "A05:2025", "severity": "MAJOR",
				   "message": " ", "suggestion": "Fix"},
				  {"file": "src/OrderController.java", "line": 1, "owaspId": "A05:2025", "severity": "MAJOR",
				   "message": "No suggestion"},
				  {"file": "src/OrderController.java", "line": 1, "owaspId": "A05:2025", "severity": "MAJOR",
				   "message": "Blank suggestion", "suggestion": " "},
				  {"file": "src/OrderController.java", "line": 1, "severity": "MAJOR",
				   "message": "No OWASP id", "suggestion": "Fix"},
				  {"file": "src/OrderController.java", "line": 1, "owaspId": "A11:2025", "severity": "MAJOR",
				   "message": "Unknown OWASP id", "suggestion": "Fix"},
				  {"file": "src/OrderController.java", "line": 0, "owaspId": "A05:2025", "severity": "MAJOR",
				   "message": "Line zero", "suggestion": "Fix"},
				  {"file": "src/OrderController.java", "owaspId": "Injection A05:2025", "severity": "minor",
				   "message": "  Kept without a line  ", "suggestion": "  Bind the value  "}
				]}
				""")), new OwaspReviewProperties());

		OwaspReviewResult result = strict.review(request("class OrderController {\n}"));

		assertThat(result.verdict()).isEqualTo(OwaspReviewResult.Verdict.COMMENT);
		assertThat(result.summary()).isEqualTo("Mixed");
		assertThat(result.findings()).containsExactly(new OwaspReviewResult.Finding("src/OrderController.java", null,
				"A05:2025", OwaspReviewResult.Severity.MINOR, "Kept without a line", "Bind the value"));
	}

	@Test
	void dropsDuplicateFindingsButKeepsNearMatches() {
		OwaspReviewAgent deduplicating = new OwaspReviewAgent(ChatClient.builder(new StubChatModel("""
				{"summary": "Duplicates", "findings": [
				  {"file": "A.java", "line": 1, "owaspId": "A05:2025", "severity": "MAJOR", "message": "Concatenated query", "suggestion": "Bind"},
				  {"file": "A.java", "line": 1, "owaspId": "A05:2025", "severity": "MAJOR", "message": "Concatenated query", "suggestion": "Bind"},
				  {"file": "A.java", "line": 2, "owaspId": "A05:2025", "severity": "MAJOR", "message": "Concatenated query", "suggestion": "Bind"},
				  {"file": "A.java", "line": 1, "owaspId": "A01:2025", "severity": "MAJOR", "message": "Concatenated query", "suggestion": "Bind"},
				  {"file": "A.java", "line": 1, "owaspId": "A05:2025", "severity": "MAJOR", "message": "Another issue", "suggestion": "Bind"},
				  {"file": "B.java", "line": 1, "owaspId": "A05:2025", "severity": "MAJOR", "message": "Concatenated query", "suggestion": "Bind"}
				]}
				""")), new OwaspReviewProperties());

		OwaspReviewResult result = deduplicating.review(new OwaspReviewRequest("billing", null, List.of(
				new RepositoryFile("A.java", "class A {\n String sql = q + name; }"),
				new RepositoryFile("B.java", "class B { String sql = q + name; }"))));

		assertThat(result.findings()).hasSize(5);
		assertThat(result.findings()).extracting(OwaspReviewResult.Finding::file)
				.containsExactly("A.java", "A.java", "A.java", "A.java", "B.java");
	}

	@Test
	void usesADefaultSummaryWhenTheModelGivesNone() {
		OwaspReviewProperties properties = new OwaspReviewProperties();
		properties.setBatchCharacters(40);
		StubChatModel model = new StubChatModel(List.of("""
				{"verdict": "COMMENT", "findings": [
				  {"file": "A.java", "line": 1, "owaspId": "A02:2025", "severity": "INFO",
				   "message": "Broad CORS", "suggestion": "List the allowed origins"}]}
				""", """
				{"summary": "  ", "verdict": "APPROVE"}
				"""));
		OwaspReviewAgent agentWithoutSummary = new OwaspReviewAgent(ChatClient.builder(model), properties);

		OwaspReviewResult result = agentWithoutSummary.review(new OwaspReviewRequest("billing", null, List.of(
				new RepositoryFile("A.java", "class A { String origins = \"*\"; }"),
				new RepositoryFile("B.java", "class B { void run() {} }"))));

		assertThat(model.prompts()).hasSize(2);
		assertThat(result.summary()).isEqualTo("Review completed.");
		assertThat(result.verdict()).isEqualTo(OwaspReviewResult.Verdict.COMMENT);
		assertThat(result.findings()).singleElement().extracting(OwaspReviewResult.Finding::owaspId)
				.isEqualTo("A02:2025");
	}

	@Test
	void approvesWhenTheModelReturnsNull() {
		OwaspReviewAgent empty = new OwaspReviewAgent(ChatClient.builder(new StubChatModel("null")),
				new OwaspReviewProperties());

		OwaspReviewResult result = empty.review(request("class OrderController {}"));

		assertThat(result.verdict()).isEqualTo(OwaspReviewResult.Verdict.APPROVE);
		assertThat(result.findings()).isEmpty();
	}

	@Test
	void doesNotCallTheModelWithoutFiles() {
		OwaspReviewResult result = agent.review(new OwaspReviewRequest("billing", null, List.of()));

		assertThat(chatModel.prompts()).isEmpty();
		assertThat(result.verdict()).isEqualTo(OwaspReviewResult.Verdict.APPROVE);
		assertThat(result.findings()).isEmpty();
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
