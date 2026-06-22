/**
 * banned.ts -- PURE: enforce the banned-reassurance-phrase contract on every
 * human-facing string the verdict emits.
 *
 * The signing-output contract (../../rules/signing-output.md and
 * ../references/verdict-contract.md) forbids reassurance language in ANY
 * verdict-describing output, unconditionally -- even for a SIGN verdict. A
 * signing gate that reassures manufactures false confidence at exactly the
 * moment the user is most exposed (the Drift April-2026 blind-signing incident
 * is the canonical example).
 *
 * Until now that contract lived only in prose. This module makes it executable:
 * buildVerdict() and rejectVerdict() run every narrative string through
 * assertNoBannedPhrase(), so a regression that reintroduces "safe"/"no risk"/
 * etc. into a reason or finding detail FAILS LOUD (throws) instead of shipping.
 * The verdict layer converts that throw into a fail-closed REJECT, so the gate
 * can never emit a reassuring SIGN.
 *
 * Matching rules:
 *   - case-insensitive,
 *   - WORD-BOUNDARY anchored, so the standalone word "safe" is banned but the
 *     skill's own name "sign-safe", the schema id "sign-safe/verdict@1", and
 *     compounds like "value-bearing" / "fail-closed" are allowed. We treat
 *     ASCII letters/digits/underscore as word characters; a hyphen is a
 *     boundary, but a banned phrase glued to letters on either side by a
 *     hyphen (e.g. "sign-safe") is NOT a match because we require the match to
 *     be bounded by non-word, non-hyphen-letter context. Concretely: "safe"
 *     matches only when neither neighbor is a word char OR a hyphen adjacent to
 *     a word char.
 */

/**
 * The forbidden reassurance substrings, lower-cased. Mirrors the list in
 * rules/signing-output.md and references/verdict-contract.md verbatim.
 * "totally safe" is a superset of "safe" but kept for explicit documentation.
 */
export const BANNED_PHRASES: readonly string[] = [
  "safe",
  "totally safe",
  "no risk",
  "looks fine",
  "you can sign this",
  "nothing dangerous",
  "trust me",
] as const;

/** Is the char at `s[i]` an ASCII word character (letter/digit/underscore)? */
function isWordChar(ch: string | undefined): boolean {
  if (ch === undefined) return false;
  return /[A-Za-z0-9_]/.test(ch);
}

/**
 * Find a banned phrase in `text` with word-boundary semantics. A phrase counts
 * as present only when it is a standalone token: the characters immediately
 * before and after the match must not be word characters, AND must not be a
 * hyphen that glues it into a larger word (so "sign-safe" and "safe-mode" do
 * not trip the bare "safe"). Returns the matched phrase, or null.
 */
export function findBannedPhrase(text: string): string | null {
  const hay = text.toLowerCase();
  for (const phrase of BANNED_PHRASES) {
    let from = 0;
    for (;;) {
      const idx = hay.indexOf(phrase, from);
      if (idx === -1) break;
      const before = idx > 0 ? hay[idx - 1] : undefined;
      const afterIdx = idx + phrase.length;
      const after = afterIdx < hay.length ? hay[afterIdx] : undefined;

      // Boundaries: neither side may be a word char. A hyphen that connects to
      // a word char on the outer side also disqualifies (it is a compound like
      // "sign-safe" or "safe-list"), which we explicitly allow.
      const beforeGlued =
        isWordChar(before) ||
        (before === "-" && isWordChar(idx > 1 ? hay[idx - 2] : undefined));
      const afterGlued =
        isWordChar(after) ||
        (after === "-" && isWordChar(afterIdx + 1 < hay.length ? hay[afterIdx + 1] : undefined));

      if (!beforeGlued && !afterGlued) {
        return phrase;
      }
      from = idx + 1;
    }
  }
  return null;
}

/**
 * Throw if `text` contains a banned reassurance phrase. `context` is included
 * in the error so a regression points at the offending field. PURE.
 */
export function assertNoBannedPhrase(text: string, context: string): void {
  const hit = findBannedPhrase(text);
  if (hit !== null) {
    throw new Error(
      `banned reassurance phrase "${hit}" found in ${context}: ${JSON.stringify(text)}`,
    );
  }
}
