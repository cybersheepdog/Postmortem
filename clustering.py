"""Campaign clustering: group related BEC messages across threads.

Buckets messages by shared strong features (URL domain, attachment, exact
subject/sender) and unions similar pairs with a union-find. Pure analysis over
EmailRecord objects; no I/O.
"""

from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional

from bechunt.config import CONFIG, PHISHING_TERMS, BUSINESS_TERMS
from bechunt.models import EmailRecord, CampaignInfo
from bechunt.utils import (
    tokenize, normalize_subject, jaccard_similarity, date_sort_key, parse_date,
)


def campaign_features(
    record: EmailRecord,
) -> dict:
 
    text = (
        record.subject
        + "\n"
        + record.body
    ).lower()
 
    return {
        "subject_tokens": tokenize(
            normalize_subject(
                record.subject
            )
        ),
 
        "body_tokens": tokenize(text),
 
        "sender": record.sender_email,

        "sender_domain": record.sender_domain,

        "date": parse_date(record.date),

        "recipients": set(
            record.recipients
            + record.cc
        ),
 
        "url_domains": set(
            record.url_domains
        ),
 
        "attachments": {
            name.lower()
            for name in record.attachments
        },
 
        "attachment_hashes": {
            x.get("sha256", "").lower()
            for x in record.attachment_details
            if x.get("sha256")
        },
 
        "attachment_types": {
            Path(name)
            .suffix
            .lower()
            for name in record.attachments
        },
 
        "phishing_terms": {
            phrase
            for phrase in PHISHING_TERMS
            if phrase in text
        },
 
        "business_terms": {
            term
            for term in BUSINESS_TERMS
            if term in text
        },
    }
 
 
def campaign_similarity(
    a: EmailRecord,
    b: EmailRecord,
    max_days: int = 30,
) -> float:
    return campaign_similarity_features(
        campaign_features(a),
        campaign_features(b),
        max_days,
    )


def campaign_similarity_features(
    fa: dict,
    fb: dict,
    max_days: int = 30,
) -> float:
    """Score two precomputed feature dicts.

    Kept separate from ``campaign_features`` so callers can compute each
    record's features once and reuse them across every pairwise comparison,
    which is the dominant cost of campaign clustering on large corpora.
    """

    score = 0.0

    # ---------------------------------------------------------------
    # Exact sender
    # ---------------------------------------------------------------
 
    if (
        fa["sender"]
        and fa["sender"] == fb["sender"]
    ):
        score += 0.30
 
    # ---------------------------------------------------------------
    # Sender domain
    # ---------------------------------------------------------------
 
    if (
        fa["sender_domain"]
        and fa["sender_domain"]
        == fb["sender_domain"]
    ):
        score += 0.12
 
    # ---------------------------------------------------------------
    # URL infrastructure
    # ---------------------------------------------------------------
 
    url_overlap = (
        fa["url_domains"]
        & fb["url_domains"]
    )
 
    if url_overlap:
        score += min(
            0.30,
            0.15
            * len(url_overlap)
        )
 
    # ---------------------------------------------------------------
    # Attachment overlap
    # ---------------------------------------------------------------
 
    attachment_overlap = (
        fa["attachments"]
        & fb["attachments"]
    )
 
    if attachment_overlap:
        score += 0.20
 
    attachment_hash_overlap = fa["attachment_hashes"] & fb["attachment_hashes"]
    if attachment_hash_overlap:
        score += 0.35
 
    attachment_type_overlap = (
        fa["attachment_types"]
        & fb["attachment_types"]
    )
 
    if attachment_type_overlap:
        score += 0.05
 
    # ---------------------------------------------------------------
    # Subject similarity
    # ---------------------------------------------------------------
 
    subject_similarity = jaccard_similarity(
        fa["subject_tokens"],
        fb["subject_tokens"],
    )
 
    if subject_similarity >= 0.5:
        score += 0.25
 
    elif subject_similarity >= 0.25:
        score += 0.12
 
    # ---------------------------------------------------------------
    # Phishing-language fingerprint
    # ---------------------------------------------------------------
 
    phishing_overlap = (
        fa["phishing_terms"]
        & fb["phishing_terms"]
    )
 
    if phishing_overlap:
 
        score += min(
            0.25,
            0.08
            * len(phishing_overlap)
        )
 
    # ---------------------------------------------------------------
    # Business-language fingerprint
    # ---------------------------------------------------------------
 
    business_overlap = (
        fa["business_terms"]
        & fb["business_terms"]
    )
 
    if business_overlap:
 
        score += min(
            0.10,
            0.03
            * len(business_overlap)
        )
 
    # ---------------------------------------------------------------
    # Recipient overlap
    # ---------------------------------------------------------------
 
    recipient_overlap = (
        fa["recipients"]
        & fb["recipients"]
    )
 
    if recipient_overlap:
        score += 0.10
 
    # ---------------------------------------------------------------
    # Time proximity
    # ---------------------------------------------------------------
 
    date_a = fa["date"]
    date_b = fb["date"]

    if date_a and date_b:
 
        days = abs(
            (
                date_a - date_b
            ).total_seconds()
        ) / 86400
 
        if days <= 1:
            score += 0.12
 
        elif days <= 3:
            score += 0.08
 
        elif days <= 7:
            score += 0.05
 
        elif days > max_days:
            score *= 0.50
 
    return min(
        1.0,
        score,
    )
 
 
def build_campaign_clusters(
    records: list[EmailRecord],
    threshold: float = 0.38,
):
    """
    Cluster related messages across independent email threads.
 
    This uses a graph approach:
 
        Email A ----similar---- Email B
                       |
                       |
                    Email C
 
    A, B and C become one campaign even if A and C are not directly
    similar enough, as long as the graph connects them.
 
    The algorithm intentionally favors high-value infrastructure
    indicators such as shared URL domains and sender infrastructure.
    """
 
    if not records:
        return []
 
    count = len(records)
 
    parent = list(range(count))
 
    def find(x):
 
        while parent[x] != x:
 
            parent[x] = parent[
                parent[x]
            ]
 
            x = parent[x]
 
        return x
 
    def union(a, b):
 
        root_a = find(a)
        root_b = find(b)
 
        if root_a != root_b:
            parent[root_b] = root_a
 
    # ------------------------------------------------------------------
    # Avoid O(n²) comparison for large corpora.
    #
    # Create buckets based on useful campaign signals first.
    # ------------------------------------------------------------------
 
    # Compute each record's campaign features exactly once and reuse them for
    # every bucketing and pairwise-similarity operation below.
    feature_cache = [campaign_features(record) for record in records]

    buckets = defaultdict(set)

    for index, record in enumerate(records):

        features = feature_cache[index]

        subject = normalize_subject(
            record.subject
        )
 
        if subject:
            buckets[
                "subject:"
                + subject
            ].add(index)
 
        if record.sender_email:
            buckets[
                "sender:"
                + record.sender_email
            ].add(index)
 
        if record.sender_domain:
            buckets[
                "senderdomain:"
                + record.sender_domain
            ].add(index)
 
        for domain in features[
            "url_domains"
        ]:
            buckets[
                "url:"
                + domain
            ].add(index)
 
        for attachment in features[
            "attachments"
        ]:
            buckets[
                "attachment:"
                + attachment
            ].add(index)
 
        for phrase in features[
            "phishing_terms"
        ]:
            buckets[
                "phish:"
                + phrase
            ].add(index)
 
    # ------------------------------------------------------------------
    # Compare within buckets and union similar pairs in a single pass.
    #
    # Strong buckets (shared URL domain, attachment, exact subject/sender) are
    # reliable campaign links. Weak buckets (sender domain, single phishing
    # term) are common; a pair sharing only a weak feature cannot reach the
    # union threshold, and any pair that can also appears in a strong bucket,
    # so oversized weak buckets are skipped. Union-find state is consulted
    # inline so pairs already in the same campaign are never re-scored.
    # ------------------------------------------------------------------
    STRONG_BUCKET_CAP = CONFIG["cluster_strong_cap"]
    WEAK_BUCKET_SKIP = CONFIG["cluster_weak_skip"]

    for key, bucket_members in buckets.items():
        if len(bucket_members) < 2:
            continue

        weak = key.startswith("senderdomain:") or key.startswith("phish:")
        if weak and len(bucket_members) > WEAK_BUCKET_SKIP:
            continue

        members = list(bucket_members)
        if len(members) > STRONG_BUCKET_CAP:
            members = members[:STRONG_BUCKET_CAP]

        for x in range(len(members)):
            a = members[x]
            root_a = find(a)
            for y in range(x + 1, len(members)):
                b = members[y]
                if find(b) == root_a:
                    continue  # already in the same campaign component
                if campaign_similarity_features(
                    feature_cache[a], feature_cache[b]
                ) >= threshold:
                    union(a, b)
                    root_a = find(a)

    # ------------------------------------------------------------------
    # Create groups
    # ------------------------------------------------------------------
 
    groups = defaultdict(list)
 
    for index in range(count):
 
        groups[
            find(index)
        ].append(index)
 
    campaigns = []
 
    campaign_number = 1
 
    for members in groups.values():
 
        # Single-message "campaigns" aren't particularly useful.
        # Still retain them as campaign_id "".
        if len(members) == 1:
            records[
                members[0]
            ].campaign_id = ""
 
            continue
 
        campaign_id = (
            f"CAMP-{campaign_number:04d}"
        )
 
        campaign_number += 1
 
        campaign_records = [
            records[index]
            for index in members
        ]
 
        campaign_score = calculate_campaign_score(
            campaign_records
        )
 
        first = min(
            campaign_records,
            key=date_sort_key,
        )
 
        last = max(
            campaign_records,
            key=date_sort_key,
        )
 
        senders = sorted({
            r.sender_email
            for r in campaign_records
            if r.sender_email
        })
 
        sender_domains = sorted({
            r.sender_domain
            for r in campaign_records
            if r.sender_domain
        })
 
        recipients = sorted({
            address
            for r in campaign_records
            for address in (
                r.recipients
                + r.cc
            )
        })
 
        subjects = sorted({
            r.subject
            for r in campaign_records
            if r.subject
        })
 
        url_domains = sorted({
            domain
            for r in campaign_records
            for domain in r.url_domains
        })
 
        attachment_names = sorted({
            name
            for r in campaign_records
            for name in r.attachments
        })
 
        attachment_types = sorted({
            Path(name)
            .suffix
            .lower()
            for r in campaign_records
            for name in r.attachments
            if Path(name).suffix
        })
 
        attachment_sha256 = sorted({
            x.get("sha256", "")
            for r in campaign_records
            for x in r.attachment_details
            if x.get("sha256")
        })
 
        shared_indicators = campaign_indicators(
            campaign_records
        )
 
        likely_origin_record = identify_campaign_origin(
            campaign_records
        )
 
        confidence = campaign_confidence(
            campaign_records,
            campaign_score,
        )
 
        campaign = CampaignInfo(
            campaign_id=campaign_id,
            campaign_score=campaign_score,
            message_count=len(
                campaign_records
            ),
            first_seen=first.date,
            last_seen=last.date,
            senders=senders,
            sender_domains=sender_domains,
            recipients=recipients,
            subjects=subjects,
            url_domains=url_domains,
            attachment_names=attachment_names,
            attachment_types=attachment_types,
            attachment_sha256=attachment_sha256,
            shared_indicators=shared_indicators,
            likely_origin=(
                likely_origin_record.path
                if likely_origin_record
                else ""
            ),
            confidence=confidence,
        )
 
        campaigns.append(
            campaign
        )
 
        # `campaign_similarity` is a per-message display metric (strongest
        # similarity to any other campaign member). Comparing every member to
        # every other is O(members^2) and dominates on large campaigns, so we
        # compare against a bounded, deterministic sample instead.
        STRONGEST_SAMPLE = CONFIG["cluster_strongest_sample"]
        sample = members[:STRONGEST_SAMPLE + 1]

        for member_index in members:

            record = records[member_index]

            record.campaign_id = (
                campaign_id
            )

            record.campaign_score = (
                campaign_score
            )

            strongest = 0.0

            for other_index in sample:

                if other_index == member_index:
                    continue

                similarity = campaign_similarity_features(
                    feature_cache[member_index],
                    feature_cache[other_index],
                )

                if similarity > strongest:
                    strongest = similarity

            record.campaign_similarity = (
                strongest
            )
 
    return sorted(
        campaigns,
        key=lambda c: (
            -c.campaign_score,
            c.first_seen,
        ),
    )
 
 
def calculate_campaign_score(
    records: list[EmailRecord],
) -> int:
 
    if not records:
        return 0
 
    scores = sorted(
        (
            r.score
            for r in records
        ),
        reverse=True,
    )
 
    # Strongest messages matter most.
    score = scores[0]
 
    # Additional suspicious messages add confidence,
    # but with diminishing weight.
    if len(scores) > 1:
        score += min(
            10,
            sum(scores[1:]) // 3,
        )
 
    # Multiple senders/domains using same infrastructure can
    # indicate a broader campaign.
    sender_domains = {
        r.sender_domain
        for r in records
        if r.sender_domain
    }
 
    url_domains = {
        domain
        for r in records
        for domain in r.url_domains
    }
 
    if len(records) >= 3:
        score += 3
 
    if len(sender_domains) >= 2:
        score += 3
 
    if url_domains:
        score += min(
            6,
            len(url_domains) * 2,
        )
 
    if any(
        r.likely_precursor
        for r in records
    ):
        score += 5
 
    return score
 
 
def campaign_indicators(
    records: list[EmailRecord],
) -> list[str]:
 
    indicators = []
 
    sender_counts = Counter(
        r.sender_email
        for r in records
        if r.sender_email
    )
 
    domain_counts = Counter(
        r.sender_domain
        for r in records
        if r.sender_domain
    )
 
    url_counts = Counter(
        domain
        for r in records
        for domain in r.url_domains
    )
 
    attachment_counts = Counter(
        Path(name).suffix.lower()
        for r in records
        for name in r.attachments
        if Path(name).suffix
    )
 
    if len(records) >= 3:
        indicators.append(
            f"Campaign contains {len(records)} related messages"
        )
 
    repeated_senders = [
        sender
        for sender, count
        in sender_counts.items()
        if count >= 2
    ]
 
    if repeated_senders:
 
        indicators.append(
            "Repeated sender identity across campaign"
        )
 
    repeated_domains = [
        domain
        for domain, count
        in domain_counts.items()
        if count >= 2
    ]
 
    if repeated_domains:
 
        indicators.append(
            "Repeated sender infrastructure/domain"
        )
 
    repeated_urls = [
        domain
        for domain, count
        in url_counts.items()
        if count >= 2
    ]
 
    if repeated_urls:
 
        indicators.append(
            "Multiple messages share URL infrastructure"
        )
 
    if attachment_counts:
 
        indicators.append(
            "Campaign contains attachment-based delivery"
        )
 
    if any(
        r.likely_precursor
        for r in records
    ):
 
        indicators.append(
            "Campaign contains a message identified as a possible precursor"
        )
 
    if any(
        r.score >= 15
        for r in records
    ):
 
        indicators.append(
            "Campaign contains a high-confidence investigation candidate"
        )
 
    return indicators
 
 
def identify_campaign_origin(
    records: list[EmailRecord],
) -> Optional[EmailRecord]:
 
    candidates = []
 
    for record in records:
 
        precursor_bonus = (
            20
            if record.likely_precursor
            else 0
        )
 
        # Earlier messages receive a small preference.
        date = parse_date(
            record.date
        )
 
        timestamp = (
            date.timestamp()
            if date
            else float("inf")
        )
 
        candidates.append(
            (
                -(
                    record.score
                    + precursor_bonus
                ),
                timestamp,
                record,
            )
        )
 
    if not candidates:
        return None
 
    candidates.sort(
        key=lambda item: (
            item[0],
            item[1],
        )
    )
 
    # Prefer a suspicious early message over the final
    # payment request.
    return candidates[0][2]
 
 
def campaign_confidence(
    records: list[EmailRecord],
    campaign_score: int,
) -> str:
 
    if campaign_score >= 35:
        return "high"
 
    if (
        campaign_score >= 22
        and len(records) >= 2
    ):
        return "medium"
 
    if (
        len(records) >= 3
        and any(
            r.likely_precursor
            for r in records
        )
    ):
        return "medium"
 
    return "low"
