import os
import re
import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from google import genai
from google.genai.errors import ServerError
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type


# ============================================================
# CONFIGURATION
# ============================================================

BLOG_DIRECTORY = Path("src/content/blog")
IMAGE_DIRECTORY = Path("public/images/blog")

TIMEZONE = ZoneInfo("Asia/Karachi")

AI_MODEL = "gemini-3.6-flash"

AUTHOR_NAME = "Abdul Muqeet Tabraiz"


# ============================================================
# RETRY HANDLING
# ============================================================

@retry(
    retry=retry_if_exception_type(ServerError),
    stop=stop_after_attempt(4),
    wait=wait_exponential(
        multiplier=2,
        min=4,
        max=30
    )
)
def generate_content_with_retry(client, model, contents):
    """
    Retry temporary Gemini server failures.

    This is intentionally limited to temporary server errors.
    We do not repeatedly retry authentication, quota, or
    malformed-request errors.
    """

    return client.models.generate_content(
        model=model,
        contents=contents,
    )


# ============================================================
# DATE / DIFFICULTY
# ============================================================

def get_today():
    """
    Get today's date using Pakistan Standard Time.

    GitHub Actions runs in UTC, so using the system date directly
    could occasionally produce the wrong publication date around
    midnight.

    Asia/Karachi is UTC+5 and does not use daylight saving time.
    """

    now = datetime.datetime.now(TIMEZONE)

    return now.date(), now


def get_difficulty_for_date(date_value):
    """
    Weekly difficulty rotation.

    Monday    -> Beginner
    Tuesday   -> Intermediate
    Wednesday -> Advanced
    Thursday  -> Expert
    Friday    -> Beginner
    Saturday  -> Intermediate
    Sunday    -> Advanced
    """

    schedule = {
        0: "Beginner",
        1: "Intermediate",
        2: "Advanced",
        3: "Expert",
        4: "Beginner",
        5: "Intermediate",
        6: "Advanced",
    }

    return schedule[date_value.weekday()]


def get_difficulty_description(difficulty):
    descriptions = {
        "Beginner": """
        The reader may have little or no professional cybersecurity
        experience.

        Explain terminology before using it.
        Use practical examples.
        Avoid assuming knowledge of enterprise security tools.
        Focus on fundamentals and why the concept matters.
        """,

        "Intermediate": """
        The reader understands basic networking, operating systems,
        common security concepts, and basic SOC terminology.

        Introduce practical defensive workflows, telemetry,
        tools, and realistic security scenarios.
        """,

        "Advanced": """
        The reader has practical cybersecurity experience.

        Discuss technical architecture, detection engineering,
        attack chains, telemetry, trade-offs, and operational
        considerations.
        Avoid oversimplifying technical details.
        """,

        "Expert": """
        The reader is an experienced cybersecurity practitioner,
        detection engineer, threat hunter, DFIR professional,
        penetration tester, security engineer, or security researcher.

        Discuss implementation details, edge cases, telemetry,
        limitations, advanced detection opportunities,
        architectural implications, and real-world trade-offs.
        Do not explain basic cybersecurity concepts unless they
        are directly relevant.
        """
    }

    return descriptions[difficulty]


# ============================================================
# TOPIC HISTORY
# ============================================================

def get_recent_topics(limit=12):
    """
    Read recent article titles from existing Markdown files.

    This helps prevent the AI from repeatedly generating nearly
    identical articles.
    """

    if not BLOG_DIRECTORY.exists():
        return []

    posts = sorted(
        BLOG_DIRECTORY.glob("*.md"),
        key=lambda path: path.stat().st_mtime,
        reverse=True
    )

    topics = []

    for post in posts[:limit]:

        try:
            content = post.read_text(encoding="utf-8")

            match = re.search(
                r'^title:\s*["\']?(.*?)["\']?\s*$',
                content,
                re.MULTILINE
            )

            if match:
                topics.append(match.group(1).strip())

        except Exception:
            continue

    return topics


# ============================================================
# SAFE SLUG
# ============================================================

def create_slug(title):
    """
    Convert a title into a filesystem-safe slug.
    """

    slug = title.lower()

    slug = re.sub(
        r"[^a-z0-9]+",
        "-",
        slug
    )

    slug = slug.strip("-")

    return slug[:80]


# ============================================================
# FRONTMATTER CLEANUP
# ============================================================

def clean_generated_content(
    content,
    publication_date,
    difficulty
):
    """
    Ensure the AI output has valid frontmatter.

    Most importantly, the publication date is ALWAYS replaced
    with the actual date calculated by Python.

    The AI is never trusted to determine the date.
    """

    content = content.strip()

    # Remove accidental Markdown code fences around the entire
    # response.
    content = re.sub(
        r"^```(?:markdown|md)?\s*",
        "",
        content,
        flags=re.IGNORECASE
    )

    content = re.sub(
        r"\s*```$",
        "",
        content
    )

    # --------------------------------------------------------
    # Locate frontmatter
    # --------------------------------------------------------

    if not content.startswith("---"):
        raise ValueError(
            "Gemini response does not start with YAML frontmatter."
        )

    parts = content.split("---", 2)

    if len(parts) != 3:
        raise ValueError(
            "Unable to parse generated Markdown frontmatter."
        )

    frontmatter = parts[1].strip()
    body = parts[2].strip()

    # --------------------------------------------------------
    # Force publication date
    # --------------------------------------------------------

    date_string = publication_date.isoformat()

    if re.search(
        r"^date\s*:",
        frontmatter,
        flags=re.MULTILINE
    ):

        frontmatter = re.sub(
            r'^date\s*:.*$',
            f'date: "{date_string}"',
            frontmatter,
            flags=re.MULTILINE
        )

    else:

        frontmatter += (
            f'\ndate: "{date_string}"'
        )

    # --------------------------------------------------------
    # Force difficulty
    # --------------------------------------------------------

    if re.search(
        r"^difficulty\s*:",
        frontmatter,
        flags=re.MULTILINE
    ):

        frontmatter = re.sub(
            r'^difficulty\s*:.*$',
            f'difficulty: "{difficulty}"',
            frontmatter,
            flags=re.MULTILINE
        )

    else:

        frontmatter += (
            f'\ndifficulty: "{difficulty}"'
        )

    # --------------------------------------------------------
    # Ensure author
    # --------------------------------------------------------

    if not re.search(
        r"^author\s*:",
        frontmatter,
        flags=re.MULTILINE
    ):

        frontmatter += (
            f'\nauthor: "{AUTHOR_NAME}"'
        )

    # --------------------------------------------------------
    # Ensure generated image field
    # --------------------------------------------------------

    if not re.search(
        r"^image\s*:",
        frontmatter,
        flags=re.MULTILINE
    ):

        # The actual filename is replaced later.
        frontmatter += '\nimage: ""'

    return (
        "---\n"
        + frontmatter.strip()
        + "\n---\n\n"
        + body.strip()
        + "\n"
    )


# ============================================================
# IMAGE GENERATION
# ============================================================

def create_blog_image(
    title,
    difficulty,
    publication_date,
    filename
):
    """
    Create a lightweight SVG hero image locally.

    This avoids:
      - copyrighted stock-image scraping
      - external image dependencies
      - broken remote image URLs
      - additional image API quotas

    The image is generated automatically for every article.
    """

    IMAGE_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True
    )

    safe_title = (
        title
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )

    difficulty_label = (
        difficulty.upper()
    )

    svg = f"""<svg
xmlns="http://www.w3.org/2000/svg"
width="1600"
height="900"
viewBox="0 0 1600 900">

<defs>

  <linearGradient
    id="background"
    x1="0%"
    y1="0%"
    x2="100%"
    y2="100%">

    <stop
      offset="0%"
      stop-color="#07111f"/>

    <stop
      offset="50%"
      stop-color="#0b1728"/>

    <stop
      offset="100%"
      stop-color="#030712"/>

  </linearGradient>

  <linearGradient
    id="accent"
    x1="0%"
    y1="0%"
    x2="100%"
    y2="0%">

    <stop
      offset="0%"
      stop-color="#22c55e"/>

    <stop
      offset="100%"
      stop-color="#06b6d4"/>

  </linearGradient>

  <filter id="glow">

    <feGaussianBlur
      stdDeviation="12"
      result="blur"/>

    <feMerge>

      <feMergeNode
        in="blur"/>

      <feMergeNode
        in="SourceGraphic"/>

    </feMerge>

  </filter>

</defs>

<!-- Background -->

<rect
  width="1600"
  height="900"
  fill="url(#background)"/>


<!-- Grid -->

<g
  opacity="0.08"
  stroke="#94a3b8"
  stroke-width="1">

  <path d="M0 100H1600"/>
  <path d="M0 200H1600"/>
  <path d="M0 300H1600"/>
  <path d="M0 400H1600"/>
  <path d="M0 500H1600"/>
  <path d="M0 600H1600"/>
  <path d="M0 700H1600"/>
  <path d="M0 800H1600"/>

  <path d="M100 0V900"/>
  <path d="M300 0V900"/>
  <path d="M500 0V900"/>
  <path d="M700 0V900"/>
  <path d="M900 0V900"/>
  <path d="M1100 0V900"/>
  <path d="M1300 0V900"/>
  <path d="M1500 0V900"/>

</g>


<!-- Decorative security nodes -->

<g
  filter="url(#glow)"
  fill="none"
  stroke="url(#accent)"
  stroke-width="3"
  opacity="0.8">

  <circle
    cx="1250"
    cy="260"
    r="120"/>

  <circle
    cx="1250"
    cy="260"
    r="80"/>

  <circle
    cx="1250"
    cy="260"
    r="40"/>

</g>


<!-- Connection lines -->

<g
  stroke="#22c55e"
  stroke-width="2"
  opacity="0.35">

  <path d="M1050 260L1170 260"/>
  <path d="M1330 260L1450 260"/>
  <path d="M1250 140V60"/>
  <path d="M1250 380V460"/>

</g>


<!-- Terminal window -->

<rect
  x="930"
  y="500"
  width="500"
  height="230"
  rx="14"
  fill="#020617"
  stroke="#1e293b"
  stroke-width="2"/>

<circle
  cx="960"
  cy="530"
  r="7"
  fill="#22c55e"/>

<circle
  cx="985"
  cy="530"
  r="7"
  fill="#06b6d4"/>

<circle
  cx="1010"
  cy="530"
  r="7"
  fill="#64748b"/>

<text
  x="960"
  y="590"
  fill="#22c55e"
  font-family="monospace"
  font-size="22">
  $ security-analysis --active
</text>

<text
  x="960"
  y="630"
  fill="#94a3b8"
  font-family="monospace"
  font-size="19">
  telemetry: enabled
</text>

<text
  x="960"
  y="665"
  fill="#94a3b8"
  font-family="monospace"
  font-size="19">
  detection: running
</text>

<text
  x="960"
  y="700"
  fill="#06b6d4"
  font-family="monospace"
  font-size="19">
  status: monitoring
</text>


<!-- Main title -->

<text
  x="120"
  y="220"
  fill="#f8fafc"
  font-family="Arial, Helvetica, sans-serif"
  font-size="64"
  font-weight="700">

  Cybersecurity Insight

</text>

<text
  x="120"
  y="310"
  fill="#cbd5e1"
  font-family="Arial, Helvetica, sans-serif"
  font-size="40"
  font-weight="600">

  {safe_title}

</text>


<!-- Difficulty -->

<rect
  x="120"
  y="370"
  width="250"
  height="54"
  rx="27"
  fill="#22c55e"
  opacity="0.14"
  stroke="#22c55e"
  stroke-width="1"/>

<text
  x="245"
  y="405"
  text-anchor="middle"
  fill="#4ade80"
  font-family="Arial, Helvetica, sans-serif"
  font-size="22"
  font-weight="700">

  {difficulty_label}

</text>


<!-- Date -->

<text
  x="120"
  y="475"
  fill="#64748b"
  font-family="monospace"
  font-size="22">

  Published {publication_date.isoformat()}

</text>


<!-- Footer -->

<text
  x="120"
  y="825"
  fill="#475569"
  font-family="monospace"
  font-size="18">

  Abdul Muqeet Tabraiz • Cybersecurity Research &amp; Security Operations

</text>

</svg>
"""

    image_path = IMAGE_DIRECTORY / filename

    image_path.write_text(
        svg,
        encoding="utf-8"
    )

    return f"/images/blog/{filename}"


# ============================================================
# AI PROMPT
# ============================================================

def build_prompt(
    publication_date,
    difficulty,
    recent_topics
):

    difficulty_description = get_difficulty_description(
        difficulty
    )

    recent_topics_text = "\n".join(
        f"- {topic}"
        for topic in recent_topics
    )

    if not recent_topics_text:
        recent_topics_text = "- None available"

    return f"""
You are writing a cybersecurity article for the personal
portfolio of {AUTHOR_NAME}.

PUBLICATION DATE:
{publication_date.isoformat()}

AUDIENCE:
{difficulty}

AUDIENCE GUIDANCE:
{difficulty_description}

IMPORTANT:
The Python program will control the publication date.
Do NOT invent a different publication date.

The article should feel like it was written by an experienced
cybersecurity practitioner who actually works with security
operations, defensive security, threat detection, networking,
systems, and security tooling.

The writing must feel natural and human.

============================================================
STYLE
============================================================

Use the same grounded, practical tone throughout the blog.

Write like a knowledgeable practitioner explaining something
to another person.

DO:

- Be direct.
- Explain why something matters.
- Use practical examples.
- Include useful technical details.
- Use natural transitions.
- Vary sentence length.
- Mention limitations where appropriate.
- Explain assumptions.
- Use realistic cybersecurity scenarios.
- Prefer concrete examples over generic statements.
- Write with confidence when the technical claim is established.
- Clearly identify uncertainty when appropriate.

DO NOT:

- Sound like a marketing article.
- Sound like an academic paper unless the topic requires it.
- Use generic AI introductions.
- Use excessive headings.
- Use repetitive conclusions.
- Repeat the title in different forms.
- Use phrases such as:
  "In today's rapidly evolving digital landscape"
  "As technology continues to evolve"
  "delve into"
  "tapestry"
  "beacon of hope"
  "revolutionize"
  "game changer"
  "in conclusion"
  "it is important to note"
- Add artificial motivational language.
- Mention that you are an AI.
- Mention this prompt.
- Mention content-generation instructions.
- Invent statistics, CVEs, threat actors, tools, or incidents.

============================================================
ARTICLE STRUCTURE
============================================================

Choose the structure that naturally fits the topic.

A strong article may include:

1. A short practical introduction
2. What the technology/attack/defensive concept actually is
3. How it works
4. Why defenders should care
5. Detection or investigation considerations
6. Practical defensive recommendations
7. Common mistakes or limitations
8. A short practical conclusion

Do not force every section if it doesn't make sense.

For technical topics, include examples such as:

- Logs
- Commands
- Event IDs
- Detection logic
- SIEM queries
- Architecture examples
- Investigation workflows
- Attack-chain context

Only include technical details that are accurate.

============================================================
SAFETY
============================================================

This is an educational cybersecurity blog.

When discussing offensive techniques:

- Explain the security implications.
- Focus on authorized testing, detection, analysis, and mitigation.
- Do not provide unnecessary operational instructions for
  compromising real systems.
- Defensive examples are preferred.

============================================================
TOPIC SELECTION
============================================================

Choose ONE strong cybersecurity topic appropriate for the
specified audience.

The topic should be useful to someone learning or practicing
cybersecurity.

Avoid repeating recent topics.

RECENT ARTICLES TO AVOID REPEATING:

{recent_topics_text}

============================================================
OUTPUT FORMAT
============================================================

Return ONLY Markdown with YAML frontmatter.

Use exactly this frontmatter structure:

---
title: "Article Title"
description: "A concise one or two sentence description."
date: "{publication_date.isoformat()}"
tags: ["Cybersecurity", "Security Operations"]
category: "Cyber Security"
difficulty: "{difficulty}"
author: "{AUTHOR_NAME}"
image: ""
---

Then write the complete article.

Do not wrap the entire response in a Markdown code block.
"""


# ============================================================
# MAIN GENERATOR
# ============================================================

def generate_natural_blog():

    api_key = os.environ.get("AI_API_KEY")

    if not api_key:

        raise ValueError(
            "AI_API_KEY environment variable is missing."
        )

    # --------------------------------------------------------
    # Date
    # --------------------------------------------------------

    today, now = get_today()

    difficulty = get_difficulty_for_date(today)

    print(
        f"Pakistan date: {today.isoformat()}"
    )

    print(
        f"Selected difficulty: {difficulty}"
    )

    # --------------------------------------------------------
    # Directories
    # --------------------------------------------------------

    BLOG_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True
    )

    IMAGE_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Existing topics
    # --------------------------------------------------------

    recent_topics = get_recent_topics()

    # --------------------------------------------------------
    # Gemini client
    # --------------------------------------------------------

    client = genai.Client(
        api_key=api_key
    )

    prompt = build_prompt(
        publication_date=today,
        difficulty=difficulty,
        recent_topics=recent_topics
    )

    # --------------------------------------------------------
    # Generate article
    # --------------------------------------------------------

    try:

        response = generate_content_with_retry(
            client=client,
            model=AI_MODEL,
            contents=prompt
        )

        post_content = response.text

    except Exception as error:

        print(
            "Failed to generate blog:"
        )

        print(error)

        raise

    if not post_content or not post_content.strip():

        raise ValueError(
            "Gemini returned an empty response."
        )

    # --------------------------------------------------------
    # Force correct metadata
    # --------------------------------------------------------

    post_content = clean_generated_content(
        content=post_content,
        publication_date=today,
        difficulty=difficulty
    )

    # --------------------------------------------------------
    # Extract title
    # --------------------------------------------------------

    title_match = re.search(
        r'^title:\s*["\']?(.*?)["\']?\s*$',
        post_content,
        re.MULTILINE
    )

    if title_match:

        title = title_match.group(1).strip()

    else:

        title = (
            f"Cybersecurity Insight - "
            f"{today.isoformat()}"
        )

    # --------------------------------------------------------
    # Create image
    # --------------------------------------------------------

    slug = create_slug(title)

    image_filename = (
        f"{today.isoformat()}-{slug}.svg"
    )

    image_url = create_blog_image(
        title=title,
        difficulty=difficulty,
        publication_date=today,
        filename=image_filename
    )

    # --------------------------------------------------------
    # Put image into frontmatter
    # --------------------------------------------------------

    post_content = re.sub(
        r'^image\s*:.*$',
        f'image: "{image_url}"',
        post_content,
        count=1,
        flags=re.MULTILINE
    )

    # --------------------------------------------------------
    # Force date ONE MORE TIME
    # --------------------------------------------------------

    post_content = re.sub(
        r'^date\s*:.*$',
        f'date: "{today.isoformat()}"',
        post_content,
        count=1,
        flags=re.MULTILINE
    )

    # --------------------------------------------------------
    # Force difficulty ONE MORE TIME
    # --------------------------------------------------------

    post_content = re.sub(
        r'^difficulty\s*:.*$',
        f'difficulty: "{difficulty}"',
        post_content,
        count=1,
        flags=re.MULTILINE
    )

    # --------------------------------------------------------
    # Save Markdown
    # --------------------------------------------------------

    filename = (
        BLOG_DIRECTORY
        / f"{today.isoformat()}-security-insight.md"
    )

    filename.write_text(
        post_content,
        encoding="utf-8"
    )

    print(
        f"Successfully generated blog: {filename}"
    )

    print(
        f"Publication date: {today.isoformat()}"
    )

    print(
        f"Difficulty: {difficulty}"
    )

    print(
        f"Hero image: {image_url}"
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    generate_natural_blog()
