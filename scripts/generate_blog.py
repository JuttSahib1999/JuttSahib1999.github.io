import os
import datetime
from google import genai

def generate_natural_blog():
    api_key = os.environ.get("AI_API_KEY")
    if not api_key:
        raise ValueError("Error: AI_API_KEY environment variable is missing or not set in GitHub repository secrets.")

    client = genai.Client(api_key=api_key)
    
    prompt = """
    You are a cyber security professional and systems analyst. 
    Write a technical, in-depth blog post about a recent trend, defensive strategy, or vulnerability analysis in the cybersecurity industry.
    
    CRITICAL STYLE GUIDELINES:
    - Write with an authoritative, grounded, and practical practitioner tone.
    - Avoid generic AI buzzwords entirely (e.g., do NOT use words like "tapestry", "delve", "beacon of hope", "revolutionize", "testament").
    - Structure it with clear markdown headings (##, ###) and practical bullet points.
    
    You must output the response strictly in the following format, including the YAML frontmatter at the top:
    
    ---
    title: "[Catchy, Technical Title Here]"
    description: "[A concise 1-2 sentence summary of the post]"
    date: "CURRENT_DATE_PLACEHOLDER"
    tags: ["Cybersecurity", "Threat Detection", "Security Operations"]
    category: "Cyber Security"
    ---
    
    [Your markdown content here]
    """
    
    try:
        # Updated model to gemini-3.6-flash which is fully supported
        response = client.models.generate_content(
            model='gemini-3.6-flash',
            contents=prompt,
        )
        post_content = response.text
    except Exception as e:
        print(f"Failed to generate content from Gemini API: {e}")
        raise e
    
    today_str = datetime.datetime.now().strftime("%Y-%m-%d")
    post_content = post_content.replace("CURRENT_DATE_PLACEHOLDER", today_str)
    
    filename_slug = f"src/content/blog/{today_str}-security-insight.md"
    os.makedirs(os.path.dirname(filename_slug), exist_ok=True)
    
    with open(filename_slug, "w", encoding="utf-8") as f:
        f.write(post_content)
    print(f"Successfully generated: {filename_slug}")

if __name__ == "__main__":
    generate_natural_blog()
