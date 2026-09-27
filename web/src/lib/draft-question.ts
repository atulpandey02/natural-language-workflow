// Hands a question typed on the home page to the new-analysis composer without
// putting it in the URL. Per-tab and best-effort: storage can be unavailable.
const KEY = "nlw:draft-question";

export function saveDraftQuestion(text: string): void {
  try {
    sessionStorage.setItem(KEY, text);
  } catch {
    /* storage unavailable: the composer simply starts empty */
  }
}

/** Returns the saved question once, then forgets it. */
export function takeDraftQuestion(): string | null {
  try {
    const text = sessionStorage.getItem(KEY);
    sessionStorage.removeItem(KEY);
    return text && text.trim() ? text : null;
  } catch {
    return null;
  }
}
