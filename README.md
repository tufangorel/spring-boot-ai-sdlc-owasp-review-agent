# Spring Boot AI OWASP Review Agent

A Spring AI service that reviews a repository snapshot for [OWASP Top 10:2025](https://owasp.org/Top10/2025/) risks. Send source files as JSON, or send a zip archive, and it returns structured findings: a summary, a verdict, and the file, line, OWASP id, severity, and fix for each issue.

The model sees only the files you send. It does not clone a Git remote, run Maven or Gradle, or query a CVE database. A03:2025 (Software Supply Chain Failures) is reported only when a build file shows a concrete issue, such as a dependency taken from an unexpected repository host. Confirming known vulnerabilities in dependencies needs a separate dependency scanner.

## OWASP Top 10:2025

| Id | Category |
|----|----------|
| A01:2025 | Broken Access Control |
| A02:2025 | Security Misconfiguration |
| A03:2025 | Software Supply Chain Failures |
| A04:2025 | Cryptographic Failures |
| A05:2025 | Injection |
| A06:2025 | Insecure Design |
| A07:2025 | Authentication Failures |
| A08:2025 | Software or Data Integrity Failures |
| A09:2025 | Security Logging and Alerting Failures |
| A10:2025 | Mishandling of Exceptional Conditions |

The service sets the verdict from the findings. `REQUEST_CHANGES` when any finding is `MAJOR` or `CRITICAL`, `COMMENT` when findings are only `MINOR` or `INFO`, otherwise `APPROVE`. Findings that name a file you did not send, or a line outside that file, are dropped.

## Tech stack

- Java 25
- Spring Boot 4.1.1 (Web MVC, Validation, Actuator)
- Spring AI 2.0.1 with the OpenAI and Anthropic model starters
- springdoc-openapi 3.1.1 (OpenAPI spec and Swagger UI)
- Maven (wrapper included)

These are the current stable releases. Milestone builds such as Spring Boot 4.2.0-M2 and Spring AI 2.1.0-M1 are not used.

## Getting started

### Prerequisites

- JDK 25
- An API key for the provider you want to use: OpenAI or Anthropic

### Run

| Setting | Values | Default |
|---------|--------|---------|
| `AI_PROVIDER` | `openai` or `anthropic` | `openai` |
| `OPENAI_MODEL` | Any OpenAI chat model | `gpt-4o-mini` |
| `ANTHROPIC_MODEL` | Any Claude model ID | `claude-haiku-4-5` |

Pass the API key as an environment variable. A key given as a command-line argument is visible in the process list and shell history.

OpenAI, Windows PowerShell:

```powershell
$env:OPENAI_API_KEY="sk-..."
.\mvnw.cmd spring-boot:run
```

OpenAI, macOS / Linux:

```bash
export OPENAI_API_KEY="sk-..."
./mvnw spring-boot:run
```

Anthropic Claude, Windows PowerShell:

```powershell
$env:AI_PROVIDER="anthropic"
$env:ANTHROPIC_API_KEY="sk-ant-..."
.\mvnw.cmd spring-boot:run
```

Build a jar with `./mvnw clean package` (`.\mvnw.cmd clean package` on Windows). The jar is `target/spring-boot-ai-sdlc-owasp-review-agent-0.0.1-SNAPSHOT.jar`.

```powershell
$env:OPENAI_API_KEY="sk-..."
java -jar target\spring-boot-ai-sdlc-owasp-review-agent-0.0.1-SNAPSHOT.jar
```

Swagger UI is at `http://localhost:8080/swagger-ui.html`. Health is at `/actuator/health`.

Source sent to this service is forwarded to the configured model provider. Do not expose the API on an untrusted network without authentication in front of it.

## API

### Review files as JSON

`POST /api/owasp-reviews`

```json
{
  "repositoryName": "billing",
  "context": "Orders API",
  "files": [
    {
      "path": "src/main/java/com/example/OrderController.java",
      "content": "@RestController\nclass OrderController {\n  @GetMapping(\"/orders/{id}\")\n  Order get(String id) {\n    return repository.findById(id);\n  }\n}\n"
    }
  ]
}
```

Paths must be relative. `..`, absolute paths, and duplicate paths are rejected.

### Review a zip archive

`POST /api/owasp-reviews/archive` as `multipart/form-data` with a part named `archive`. Optional form fields: `repositoryName` and `context`. When `repositoryName` is omitted, the zip file name is used.

The reader keeps source and config files (`.java`, `.kt`, `.xml`, `.yml`, `.yaml`, `.properties`, `.gradle`, `Dockerfile`, and similar) and skips build output (`target`, `build`, `.git`, `.gradle`, `node_modules`) and binary files. The archive is not executed.

### Response

```json
{
  "summary": "Missing access check",
  "verdict": "REQUEST_CHANGES",
  "findings": [
    {
      "file": "src/main/java/com/example/OrderController.java",
      "line": 4,
      "owaspId": "A01:2025",
      "severity": "CRITICAL",
      "message": "The order id is taken from the caller with no ownership check",
      "suggestion": "Authorize the caller against the order before returning it"
    }
  ]
}
```

### Limits

| Property | Default |
|----------|---------|
| `owasp.review.max-files` | 40 |
| `owasp.review.max-file-characters` | 100000 |
| `owasp.review.max-total-characters` | 400000 |
| `owasp.review.batch-characters` | 80000 |
| `owasp.review.max-archive-bytes` | 8000000 |
| `owasp.review.max-archive-entries` | 1000 |

Files are sent to the model in batches so a snapshot can exceed one prompt. Findings from every batch are merged, and the verdict is calculated once for the whole snapshot.

## Tests

```bash
./mvnw verify
```

On Windows: `.\mvnw.cmd verify`.

The tests use a stub chat model. They do not call OpenAI or Anthropic.
