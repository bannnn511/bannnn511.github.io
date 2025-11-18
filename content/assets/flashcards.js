(function () {
  "use strict";

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  function init() {
    const container = document.querySelector(".flashcard-container");
    if (!container) return;

    let gptEnabled = container.getAttribute("data-gpt-enabled") === "true";
    let gptConfig = null;

    if (gptEnabled) {
      const configEl = document.getElementById("flashcard-config");
      if (configEl && configEl.textContent) {
        try {
          gptConfig = JSON.parse(configEl.textContent);
        } catch (error) {
          console.error("Failed to parse GPT configuration:", error);
          gptEnabled = false;
        }
      } else {
        gptEnabled = false;
      }
    }

    const wrapper = container.querySelector(".flashcard-wrapper");
    if (!wrapper) return;

    const cards = Array.from(wrapper.querySelectorAll(".flashcard"));
    if (cards.length === 0) return;

    const prevButton = document.getElementById("prev-card");
    const nextButton = document.getElementById("next-card");
    const counter = document.getElementById("card-counter");

    const shuffledCards = shuffle(cards);
    shuffledCards.forEach((card) => wrapper.appendChild(card));

    let currentCardIndex = 0;
    const totalCards = shuffledCards.length;

    shuffledCards.forEach((card) => {
      card.classList.remove("flipped");
      card.classList.remove("active");

      const back = card.querySelector(".flashcard-back");
      if (back) {
        back.addEventListener("click", (event) => {
          event.preventDefault();
          event.stopPropagation();
          card.classList.remove("flipped");
        });
      }

      setupAnswerForm(card, {
        config: gptConfig,
        gptEnabled,
      });
    });

    updateCard();

    if (prevButton) {
      prevButton.addEventListener("click", () => {
        if (currentCardIndex > 0) {
          currentCardIndex -= 1;
          updateCard();
        }
      });
    }

    if (nextButton) {
      nextButton.addEventListener("click", () => {
        if (currentCardIndex < totalCards - 1) {
          currentCardIndex += 1;
          updateCard();
        }
      });
    }

    document.addEventListener("keydown", (event) => {
      const activeElement = document.activeElement;
      if (
        activeElement && ["INPUT", "TEXTAREA"].includes(activeElement.tagName)
      ) {
        return;
      }

      if (event.key === "ArrowLeft") {
        event.preventDefault();
        if (currentCardIndex > 0) {
          currentCardIndex -= 1;
          updateCard();
        }
      } else if (event.key === "ArrowRight") {
        event.preventDefault();
        if (currentCardIndex < totalCards - 1) {
          currentCardIndex += 1;
          updateCard();
        }
      } else if (event.key === " " || event.key === "Enter") {
        event.preventDefault();
        const activeCard = shuffledCards[currentCardIndex];
        if (activeCard) {
          activeCard.classList.toggle("flipped");
        }
      }
    });

    function updateCard() {
      shuffledCards.forEach((card, index) => {
        if (index === currentCardIndex) {
          card.classList.add("active");
        } else {
          card.classList.remove("active");
        }
        card.classList.remove("flipped");

        resetAnswerForm(card);
      });

      if (counter) {
        counter.textContent = `${currentCardIndex + 1} / ${totalCards}`;
      }

      if (prevButton) {
        prevButton.disabled = currentCardIndex === 0;
      }

      if (nextButton) {
        nextButton.disabled = currentCardIndex === totalCards - 1;
      }
    }

    function resetAnswerForm(card) {
      const form = card.querySelector(".answer-form");
      if (!form) return;

      const textarea = form.querySelector("textarea");
      const feedback = form.querySelector(".answer-feedback");
      const checkButton = form.querySelector(".check-answer");

      if (textarea) {
        textarea.value = "";
      }
      if (feedback) {
        feedback.textContent = "";
        feedback.classList.remove("success", "partial", "failure", "error");
      }
      if (checkButton) {
        checkButton.disabled = false;
        const gradingMode = checkButton.dataset.grading === "llm"
          ? "llm"
          : "simple";
        if (gradingMode === "llm") {
          checkButton.textContent = "Check with AI";
          checkButton.classList.add("use-llm");
        } else {
          checkButton.textContent = "Check (exact match)";
          checkButton.classList.remove("use-llm");
        }
      }
    }

    function setupAnswerForm(card, { config, gptEnabled }) {
      const form = card.querySelector(".answer-form");
      if (!form) return;

      const textarea = form.querySelector("textarea");
      const checkButton = form.querySelector(".check-answer");
      const revealButton = form.querySelector(".show-answer");
      const feedback = form.querySelector(".answer-feedback");
      const hideButton = card.querySelector(".hide-answer");

      const initialMode = checkButton?.dataset.grading === "llm"
        ? "llm"
        : "simple";
      const gradingMode = gptEnabled ? initialMode : "simple";
      if (checkButton) {
        checkButton.dataset.grading = gradingMode;
      }

      if (revealButton) {
        revealButton.addEventListener("click", (event) => {
          event.preventDefault();
          event.stopPropagation();
          card.classList.add("flipped");
        });
      }

      if (hideButton) {
        hideButton.addEventListener("click", (event) => {
          event.preventDefault();
          event.stopPropagation();
          card.classList.remove("flipped");
        });
      }

      if (textarea) {
        textarea.addEventListener("keydown", (event) => {
          if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
            event.preventDefault();
            checkButton?.click();
          }
        });
      }

      if (checkButton && textarea && feedback) {
        if (gradingMode === "llm") {
          checkButton.textContent = "Check with AI";
          checkButton.classList.add("use-llm");
        } else {
          checkButton.dataset.grading = "simple";
          checkButton.textContent = "Check (exact match)";
          checkButton.classList.remove("use-llm");
        }

        checkButton.addEventListener("click", async (event) => {
          event.preventDefault();
          event.stopPropagation();
          await evaluateAnswer({
            card,
            textarea,
            feedback,
            button: checkButton,
            config,
          });
        });
      }
    }

    async function evaluateAnswer(
      { card, textarea, feedback, button, config },
    ) {
      const userAnswer = textarea.value.trim();
      if (!userAnswer) {
        feedback.textContent = "Please enter an answer before checking.";
        feedback.classList.remove("success", "partial", "failure", "error");
        feedback.classList.add("failure");
        return;
      }

      button.disabled = true;
      const originalLabel = button.textContent;
      button.textContent = "Checking…";

      const question = extractText(
        card.querySelector(".flashcard-front .flashcard-content"),
      );
      const expected = extractText(
        card.querySelector(".flashcard-back .flashcard-content"),
      );

      try {
        const result = await gradeAnswer({
          question,
          expected,
          userAnswer,
          config,
        });

        feedback.textContent = result.message;
        feedback.classList.remove("success", "partial", "failure", "error");
        feedback.classList.add(result.status);
        card.classList.add("flipped");
      } catch (error) {
        console.error("Unable to grade flashcard answer", error);
        feedback.textContent =
          "Could not verify answer. Showing the reference.";
        feedback.classList.remove("success", "partial", "failure", "error");
        feedback.classList.add("error");
        card.classList.add("flipped");
      } finally {
        button.disabled = false;
        button.textContent = originalLabel;
      }
    }

    async function gradeAnswer({ question, expected, userAnswer, config }) {
      const fallback = simpleCompare(userAnswer, expected);
      if (!config || !config.apiKey) {
        return fallback;
      }

      try {
        const evaluation = await requestGPT({
          question,
          expected,
          userAnswer,
          config,
        });

        if (!evaluation) {
          return fallback;
        }

        return evaluation;
      } catch (error) {
        return fallback;
      }
    }
  }

  function shuffle(array) {
    const items = [...array];
    for (let i = items.length - 1; i > 0; i -= 1) {
      const j = Math.floor(Math.random() * (i + 1));
      [items[i], items[j]] = [items[j], items[i]];
    }
    return items;
  }

  function extractText(node) {
    if (!node) return "";
    return (node.textContent || "").replace(/\s+/g, " ").trim();
  }

  function normalizeText(value) {
    return value
      .toLowerCase()
      .replace(/<[^>]*>/g, " ")
      .replace(/[^a-z0-9\s]/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  }

  function simpleCompare(userAnswer, expected) {
    const normalizedUser = normalizeText(userAnswer);
    const normalizedExpected = normalizeText(expected);

    if (normalizedUser && normalizedUser === normalizedExpected) {
      return {
        status: "success",
        message: "Correct! Nice work.",
      };
    }

    if (
      normalizedUser && normalizedExpected &&
      (normalizedUser.includes(normalizedExpected) ||
        normalizedExpected.includes(normalizedUser))
    ) {
      return {
        status: "partial",
        message: "Close! Review the full answer for more detail.",
      };
    }

    return {
      status: "failure",
      message: "Not quite. Reveal the answer to review.",
    };
  }

  async function requestGPT({ question, expected, userAnswer, config }) {
    const endpoint = config.endpoint ||
      "https://api.openai.com/v1/chat/completions";
    const model = config.model || "gpt-4o-mini";

    const controller = typeof AbortController !== "undefined"
      ? new AbortController()
      : null;
    const timeoutId = controller
      ? setTimeout(() => controller.abort(), 10000)
      : null;

    try {
      const body = {
        model,
        temperature: 0,
        messages: [
          {
            role: "system",
            content:
              'You are a precise flashcard grading assistant performing semantic answer grading. Assess whether the learner answer conveys the SAME meaning as the reference answer using conceptual understanding, paraphrase recognition, synonym handling, and domain reasoning (CS, medical, math, etc.). Detect partial answers when key ideas are missing and flag vague or incomplete wording. Respond ONLY with compact JSON (no code fences, no extra text) shaped exactly as {"result":"correct"|"partial"|"incorrect","reason":"short explanation"} where "reason" highlights the most important justification in under 20 words.',
          },
          {
            role: "user",
            content:
              `Question: ${question}\nReference answer: ${expected}\nLearner answer: ${userAnswer}`,
          },
        ],
      };

      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${config.apiKey}`,
        },
        body: JSON.stringify(body),
        signal: controller ? controller.signal : undefined,
      });

      if (!response.ok) {
        throw new Error(`GPT request failed with status ${response.status}`);
      }

      const payload = await response.json();
      const message = payload?.choices?.[0]?.message?.content ?? "";
      const parsed = parseGradingPayload(message);
      if (!parsed) {
        return null;
      }

      return normalizeEvaluation(parsed);
    } finally {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
    }
  }

  function normalizeEvaluation(result) {
    if (!result || typeof result !== "object") return null;

    const outcome = typeof result.result === "string"
      ? result.result.toLowerCase()
      : "";
    const reason =
      typeof result.reason === "string" && result.reason.trim().length > 0
        ? result.reason.trim()
        : null;

    if (outcome === "correct") {
      return {
        status: "success",
        message: reason || "Correct! Nice work.",
      };
    }

    if (outcome === "partial") {
      return {
        status: "partial",
        message: reason || "Almost there. Compare with the reference answer.",
      };
    }

    if (outcome === "incorrect") {
      return {
        status: "failure",
        message: reason || "Not quite. Review the reference answer.",
      };
    }

    return null;
  }

  function parseGradingPayload(text) {
    if (!text) return null;
    const trimmed = text.trim();
    if (trimmed === "") return null;

    const cleaned = trimmed
      .replace(/```json\s*/gi, "")
      .replace(/```/g, "")
      .trim();

    const direct = tryParseJSON(cleaned);
    if (direct) return direct;

    const braceMatch = cleaned.match(/\{[\s\S]*\}/);
    if (braceMatch) {
      const candidate = tryParseJSON(braceMatch[0]);
      if (candidate) return candidate;
    }

    return null;
  }

  function tryParseJSON(value) {
    try {
      return JSON.parse(value);
    } catch {
      return null;
    }
  }
})();
