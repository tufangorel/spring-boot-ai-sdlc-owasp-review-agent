package org.example.owasp.review;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.Prompt;

class StubChatModel implements ChatModel {

	private final Deque<String> replies = new ArrayDeque<>();

	private final RuntimeException failure;

	private final List<Prompt> prompts = new ArrayList<>();

	StubChatModel(String reply) {
		this.replies.add(reply);
		this.failure = null;
	}

	StubChatModel(List<String> replies) {
		this.replies.addAll(replies);
		this.failure = null;
	}

	private StubChatModel(RuntimeException failure) {
		this.failure = failure;
	}

	static StubChatModel failingWith(RuntimeException failure) {
		return new StubChatModel(failure);
	}

	@Override
	public ChatResponse call(Prompt prompt) {
		prompts.add(prompt);
		if (failure != null) {
			throw failure;
		}
		String reply = replies.size() > 1 ? replies.removeFirst() : replies.getFirst();
		return new ChatResponse(List.of(new Generation(new AssistantMessage(reply))));
	}

	List<Prompt> prompts() {
		return prompts;
	}

	Prompt lastPrompt() {
		return prompts.getLast();
	}

}
