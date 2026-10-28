import { buildJudgeUserPrompt, type JudgeProvider, JUDGE_SYSTEM_PROMPT, parseJudgeResponse } from "@safety-core/core";

type JudgeOptions = {
  readonly apiKey: string;
  readonly model?: string;
  readonly baseUrl?: string;
};

export function buildOpenCodeJudgeProvider(): JudgeProvider | null {
  if (process.env.ANTHROPIC_API_KEY) return createAnthropicJudge({ apiKey: process.env.ANTHROPIC_API_KEY });
  if (process.env.OPENAI_API_KEY) return createOpenAIJudge({ apiKey: process.env.OPENAI_API_KEY });
  return null;
}

export function createAnthropicJudge(options: JudgeOptions): JudgeProvider {
  const baseUrl = options.baseUrl ?? process.env.ANTHROPIC_BASE_URL ?? "https://api.anthropic.com/v1";
  const hasAuthToken = Boolean(process.env.ANTHROPIC_AUTH_TOKEN);
  return async (command, signal) => {
    try {
      const response = await fetch(`${baseUrl}/messages`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": options.apiKey,
          "anthropic-version": "2023-06-01",
          ...(hasAuthToken ? { authorization: `Bearer ${options.apiKey}` } : {}),
        },
        body: JSON.stringify({
          model: options.model ?? "claude-haiku-4-5",
          max_tokens: 256,
          system: JUDGE_SYSTEM_PROMPT,
          messages: [{ role: "user", content: buildJudgeUserPrompt(command) }],
        }),
        ...(signal === undefined ? {} : { signal }),
      });
      if (!response.ok) return unavailable(response.status);
      const body = (await response.json()) as { content?: Array<{ type: string; text?: string }> };
      return parseJudgeResponse(
        body.content
          ?.filter((content) => content.type === "text")
          .map((content) => content.text ?? "")
          .join("") ?? "",
      );
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") throw error;
      return judgeError();
    }
  };
}

export function createOpenAIJudge(options: JudgeOptions): JudgeProvider {
  const baseUrl = (options.baseUrl ?? process.env.OPENAI_BASE_URL ?? "https://api.openai.com/v1").replace(/\/$/, "");
  return async (command, signal) => {
    try {
      const response = await fetch(`${baseUrl}/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${options.apiKey}` },
        body: JSON.stringify({
          model: options.model ?? "gpt-4o-mini",
          max_tokens: 256,
          temperature: 0,
          messages: [
            { role: "system", content: JUDGE_SYSTEM_PROMPT },
            { role: "user", content: buildJudgeUserPrompt(command) },
          ],
        }),
        ...(signal === undefined ? {} : { signal }),
      });
      if (!response.ok) return unavailable(response.status);
      const body = (await response.json()) as { choices?: Array<{ message?: { content?: string } }> };
      return parseJudgeResponse(body.choices?.[0]?.message?.content ?? "");
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") throw error;
      return judgeError();
    }
  };
}

function unavailable(status: number) {
  return { safe: true, reasoning: `Judge unavailable (HTTP ${status}); allowing by default`, fromLLM: true };
}

function judgeError() {
  return { safe: true, reasoning: "Judge error; allowing by default", fromLLM: true };
}
