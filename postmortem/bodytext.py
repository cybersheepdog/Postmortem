"""Separate a message's own words from everything it merely carries.

Language scoring used to run over the whole body, which meant it also scored
the quoted reply history and the corporate confidentiality footer. Both are
noise, and both are pervasive:

  * A standard legal disclaimer matches "confidential" and satisfies the
    secrecy half of the payment+secrecy combination, so an ordinary
    accounts-payable email scores as though it asked for secrecy.
  * Quoted history means one phishing message's language is present in, and
    scored on, every later reply in its thread -- and a colleague's innocent
    "see below" inherits the attacker's whole vocabulary.

This module splits a body into three regions: the words this sender actually
wrote, the quoted history beneath them, and trailing boilerplate. Scoring reads
the first; the second is still examined, but only to tell the analyst when it
contains something the message's own text does not, so excluding it never
becomes a blind spot.

Boilerplate is identified by repetition across the corpus rather than by a word
list, which is language-agnostic and catches whatever footer an organization
actually uses. That carries a specific danger: an attacker who has taken over
an account and mass-mails a lure from it produces a repeated block too, and
suppressing it would hide the attack instead of the boilerplate. Four guards
separate the two, and the same index raises a finding on the pattern it must
not suppress. See :class:`BoilerplateIndex`.
"""

import hashlib
import re

from postmortem.utils import parse_date

# --------------------------------------------------------------------------
# Quoted history
# --------------------------------------------------------------------------
# The point where a reply stops being new text. Ordered by how unambiguous each
# marker is; the earliest match in the body wins.
_QUOTE_MARKERS = (
    # Outlook / Exchange
    re.compile(r"^\s*-{2,}\s*Original Message\s*-{2,}\s*$", re.I | re.M),
    re.compile(r"^\s*-{2,}\s*Forwarded message\s*-{2,}", re.I | re.M),
    re.compile(r"^\s*_{10,}\s*$", re.M),
    # "From: x  Sent: y  To: z" header block pasted into the body
    re.compile(r"^\s*From:.{0,200}$\s*^\s*(?:Sent|Date):", re.I | re.M),
    # Gmail / Apple Mail attribution, optionally wrapped across two lines
    re.compile(r"^\s*On\s.{0,300}?\swrote:\s*$", re.I | re.M | re.S),
    re.compile(r"^\s*El\s.{0,300}?\sescribió:\s*$", re.I | re.M | re.S),
    re.compile(r"^\s*Le\s.{0,300}?\sa écrit\s*:\s*$", re.I | re.M | re.S),
    re.compile(r"^\s*Am\s.{0,300}?\sschrieb\s.{0,120}:\s*$", re.I | re.M | re.S),
)

# Scanned as a single alternation: eight separate searches meant eight passes
# over the whole body, which on a large message dominated the split.
_QUOTE_MARKER = re.compile(
    "|".join("(?:%s)" % p.pattern for p in _QUOTE_MARKERS),
    re.I | re.M)

_QUOTED_LINE = re.compile(r"^\s*>")

# RFC 3676 signature delimiter, and the common typed variants.
_SIG_DELIM = re.compile(r"^\s*(?:--\s?|__+|—-)\s*$", re.M)

# Only used when the corpus is too small for repetition statistics to mean
# anything. Deliberately short: the corpus index is the real mechanism.
_DISCLAIMER_HINTS = re.compile(
    r"(this (?:e-?mail|message)[^.]{0,80}(?:and any attachments?|is confidential)"
    r"|intended (?:solely|only) for"
    r"|if you (?:have )?received this (?:e-?mail |message )?in error"
    r"|unsubscribe"
    r"|privileged and confidential"
    r"|please consider the environment)", re.I)


def split_quoted(body: str):
    """Return ``(own_text, quoted_text)``.

    Top-posting is assumed -- the overwhelmingly common case -- so everything
    from the earliest quote marker onward is history. Interleaved ``>`` lines
    above that point are dropped from the own text as well.
    """
    if not body:
        return "", ""

    match = _QUOTE_MARKER.search(body)
    cut = match.start() if match else None

    if cut is None:
        own, quoted = body, ""
    else:
        own, quoted = body[:cut], body[cut:]

    # Interleaved quoting: a run of ">" lines is history wherever it appears.
    kept, moved = [], []
    for line in own.splitlines():
        (moved if _QUOTED_LINE.match(line) else kept).append(line)
    if moved:
        quoted = "\n".join(moved) + ("\n" + quoted if quoted else "")

    return "\n".join(kept).strip(), quoted.strip()


def strip_signature(text: str, max_signature_lines: int = 20):
    """Drop a trailing signature block introduced by a delimiter line.

    Bounded by line count so a delimiter used mid-message as a horizontal rule
    cannot swallow the rest of a long email.
    """
    if not text:
        return "", ""
    matches = list(_SIG_DELIM.finditer(text))
    if not matches:
        return text, ""
    last = matches[-1]
    tail = text[last.end():]
    if tail.count("\n") > max_signature_lines:
        return text, ""
    return text[:last.start()].rstrip(), tail.strip()


def blocks(text: str, min_chars: int = 60):
    """Split into paragraph blocks worth indexing, longest-lived first."""
    out = []
    for raw in re.split(r"\n\s*\n", text or ""):
        block = raw.strip()
        if len(block) >= min_chars:
            out.append(block)
    return out


# Blocks are compared on a bounded prefix: boilerplate and lures are far
# shorter than this, and it keeps a single very long paragraph from costing
# more to normalize than the rest of the message put together.
BLOCK_COMPARE_CHARS = 2000


def normalize_block(block: str) -> str:
    """Collapse a block to a comparable form.

    Whitespace and case vary with mail clients; digits and URLs vary per
    message (dates, reference numbers, tracking links) while the surrounding
    boilerplate is identical, so they are masked rather than compared.
    """
    text = block[:BLOCK_COMPARE_CHARS].lower()
    text = re.sub(r"https?://\S+", " url ", text)
    text = re.sub(r"\d+", "0", text)
    return re.sub(r"\s+", " ", text).strip()


def block_hash(block: str) -> str:
    return hashlib.sha1(
        normalize_block(block).encode("utf-8", "replace")).hexdigest()[:16]


# --------------------------------------------------------------------------
# Corpus repetition
# --------------------------------------------------------------------------
class BoilerplateIndex:
    """Learn which repeated blocks are institutional, and which are a blast.

    Repetition alone cannot tell a corporate disclaimer from the lure an
    attacker mass-mails out of a compromised mailbox -- both appear in many
    messages. Suppressing the second would hide the attack, and would also
    strip it out of campaign clustering, which is the thing meant to catch it.

    A block is treated as boilerplate only when all of these hold:

      * it sits in the message's trailing region, where footers live and lures
        do not;
      * it was sent by several distinct senders, as an organization's footer is
        and a single compromised account's blast is not;
      * its occurrences span a wide time range, rather than a burst; and
      * where a compromise date is known, it was already in use before it.

    The same counts, read the other way, identify the blast: a block repeated
    from one sender inside a narrow window. That is reported as a finding
    rather than suppressed.
    """

    def __init__(self, min_count=5, min_senders=3, min_span_days=7.0,
                 burst_min_count=8, burst_max_hours=72.0):
        self.min_count = min_count
        self.min_senders = min_senders
        self.min_span_days = min_span_days
        self.burst_min_count = burst_min_count
        self.burst_max_hours = burst_max_hours
        self.stats = {}
        self._boilerplate = set()
        self._bursts = {}
        self._finalized = False

    def observe(self, record, own_text: str):
        """Record every block of one message's own text."""
        when = parse_date(getattr(record, "date", "") or "")
        sender = str(getattr(record, "sender_email", "") or "")
        pre = bool(getattr(record, "is_pre_compromise", False))

        found = blocks(own_text)
        for position, block in enumerate(found):
            digest = block_hash(block)
            entry = self.stats.get(digest)
            if entry is None:
                entry = self.stats[digest] = {
                    "count": 0, "senders": set(), "first": None, "last": None,
                    "pre_compromise": False, "trailing": 0, "paths": [],
                }
            entry["count"] += 1
            if sender:
                entry["senders"].add(sender)
            if when is not None:
                if entry["first"] is None or when < entry["first"]:
                    entry["first"] = when
                if entry["last"] is None or when > entry["last"]:
                    entry["last"] = when
            entry["pre_compromise"] = entry["pre_compromise"] or pre
            # Trailing = the last block of the message. Footers live there.
            if position == len(found) - 1:
                entry["trailing"] += 1
            if len(entry["paths"]) < 25:
                entry["paths"].append(str(getattr(record, "path", "")))

    def finalize(self, compromise_known: bool = False):
        """Classify every observed block. Returns a summary dict."""
        self._boilerplate.clear()
        self._bursts.clear()

        for digest, entry in self.stats.items():
            count = entry["count"]
            senders = len(entry["senders"])
            span_days = 0.0
            if entry["first"] and entry["last"]:
                span_days = (entry["last"] - entry["first"]).total_seconds() / 86400.0

            mostly_trailing = entry["trailing"] >= count * 0.6

            if (count >= self.min_count
                    and mostly_trailing
                    and senders >= self.min_senders
                    and span_days >= self.min_span_days
                    and (not compromise_known or entry["pre_compromise"])):
                self._boilerplate.add(digest)
                continue

            # The inverse pattern: many copies, one sender, short window.
            span_hours = span_days * 24.0
            if (count >= self.burst_min_count
                    and senders == 1
                    and span_hours <= self.burst_max_hours):
                self._bursts[digest] = {
                    "count": count,
                    "sender": next(iter(entry["senders"]), ""),
                    "hours": round(span_hours, 1),
                    "paths": list(entry["paths"]),
                }

        self._finalized = True
        return {
            "blocks_seen": len(self.stats),
            "boilerplate_blocks": len(self._boilerplate),
            "burst_blocks": len(self._bursts),
        }

    @property
    def usable(self) -> bool:
        """True when repetition statistics mean anything on this corpus."""
        return self._finalized and bool(self._boilerplate)

    def is_boilerplate(self, digest: str) -> bool:
        return digest in self._boilerplate

    def burst_for(self, digest: str):
        return self._bursts.get(digest)

    def bursts(self):
        return dict(self._bursts)

    def strip(self, own_text: str, fallback_patterns: bool = True):
        """Remove boilerplate blocks from a message's own text.

        Returns ``(scored_text, removed_blocks)``. When the corpus is too small
        for the index to have identified anything, falls back to the short
        disclaimer hint list so small mailboxes are not left unprotected.
        """
        if not own_text:
            return "", []

        found = blocks(own_text, min_chars=1)
        if not found:
            return own_text, []

        kept, removed = [], []
        for position, block in enumerate(found):
            digest = block_hash(block)
            drop = self.is_boilerplate(digest)
            if not drop and fallback_patterns and not self.usable:
                # Only trailing blocks are eligible for the pattern fallback,
                # so a lure in the body proper can never match it.
                if position >= len(found) - 2 and _DISCLAIMER_HINTS.search(block):
                    drop = True
            (removed if drop else kept).append(block)
        return "\n\n".join(kept).strip(), removed


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------
# Terms worth telling the analyst about when they appear only in quoted text.
_QUOTED_SIGNAL_TERMS = (
    "wire transfer", "bank details", "change bank", "new bank account",
    "updated bank details", "gift card", "verify your account",
    "confirm your identity", "reset your password", "account suspended",
    "keep this confidential", "do not tell", "remittance",
)


def prepare_bodies(records, compromise_date=None, index=None):
    """Populate `body_own`, `quoted_signals` and burst markers on every record.

    Two passes. The first observes each message's own text so the corpus can
    say which blocks are institutional boilerplate and which are a mass-mailed
    burst; the second applies that verdict. Splitting it this way is what makes
    the distinction possible at all -- neither can be decided from a single
    message.
    """
    index = index or BoilerplateIndex()
    own_by_path = {}
    quoted_by_path = {}

    for record in records:
        own, quoted = split_quoted(getattr(record, "body", "") or "")
        own, _signature = strip_signature(own)
        own_by_path[id(record)] = own
        quoted_by_path[id(record)] = quoted

        pre = getattr(record, "is_pre_compromise", False)
        if compromise_date is not None:
            when = parse_date(getattr(record, "date", "") or "")
            pre = bool(when and when <= compromise_date)
            record.is_pre_compromise = pre
        index.observe(record, own)

    summary = index.finalize(compromise_known=compromise_date is not None)

    stripped = 0
    for record in records:
        own = own_by_path[id(record)]
        quoted = quoted_by_path[id(record)]
        scored, removed = index.strip(own)
        if removed:
            stripped += 1

        full = getattr(record, "body", "") or ""
        # Only store the reduced text when it actually differs, so a plain
        # message with no reply chain and no footer costs nothing extra.
        record.body_own = scored if scored.strip() != full.strip() else ""

        if quoted:
            own_lower = scored.lower()
            quoted_lower = quoted.lower()
            record.quoted_signals = [
                term for term in _QUOTED_SIGNAL_TERMS
                if term in quoted_lower and term not in own_lower
            ]

        for block in blocks(scored):
            burst = index.burst_for(block_hash(block))
            if burst and burst["count"] > record.burst_copies:
                record.burst_copies = burst["count"]
                record.burst_hours = burst["hours"]

    summary["messages_reduced"] = stripped
    return summary, index


def scoring_text(record) -> str:
    """The text language scoring should read for this record."""
    own = getattr(record, "body_own", "") or ""
    return own if own else (getattr(record, "body", "") or "")
