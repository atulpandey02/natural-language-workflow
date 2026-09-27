"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { saveDraftQuestion } from "@/lib/draft-question";

/** The conversational entry point: ask in plain language or start from a sample. */
export function HomeComposer() {
  const router = useRouter();
  const [question, setQuestion] = useState("");
  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!question.trim()) return;
    saveDraftQuestion(question.trim());
    router.push("/workflows/new");
  }
  return (
    <section className="home-composer" aria-labelledby="home-composer-title">
      <h2 id="home-composer-title">Ask a business question</h2>
      <p className="muted small">
        NLW drafts a workflow for you to review. Nothing runs until you choose to.
      </p>
      <form onSubmit={submit}>
        <div>
          <label className="sr-only" htmlFor="home-question">
            Your question
          </label>
          <textarea
            id="home-question"
            rows={2}
            maxLength={4000}
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="e.g. Which product categories declined over the last six months?"
          />
        </div>
        <button type="submit" disabled={!question.trim()}>
          Prepare plan →
        </button>
      </form>
      <p className="section-title">Or start from a sample workflow</p>
      <div className="next-actions" data-testid="sample-choices">
        <Link href="/workflows/new?dataset=sales-v1">
          <span className="choice-icon" aria-hidden="true">
            ↗
          </span>
          <strong>Sales performance</strong>
          <span>Revenue, orders, categories and regions — synthetic data.</span>
        </Link>
        <Link href="/workflows/new?dataset=support-v1">
          <span className="choice-icon" aria-hidden="true">
            ◎
          </span>
          <strong>Support operations</strong>
          <span>SLA compliance, backlog and satisfaction — synthetic data.</span>
        </Link>
        <div className="disabled-choice" aria-disabled="true">
          <span className="choice-icon" aria-hidden="true">
            ⚇
          </span>
          <strong>Staffing and capacity</strong>
          <span>Not in this pilot. Only the Sales and Support samples are available.</span>
        </div>
      </div>
    </section>
  );
}
