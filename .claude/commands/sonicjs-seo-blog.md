# Generate SEO-Optimized Blog Post

Generate a high-quality, SEO-optimized blog post for SonicJS on the topic: $ARGUMENTS

## Instructions

1. **Research Phase**:
   - Search the web for current trends and competitor content on this topic
   - Identify the primary keyword and 3-5 secondary keywords
   - Find the search intent (informational, transactional, navigational)

2. **Content Creation**:
   - Write a comprehensive blog post (1500-2500 words)
   - Use proper heading hierarchy (H1 > H2 > H3)
   - **IMPORTANT**: Include a TL;DR box with Key Stats immediately after the H1 (see format below)
   - Include code examples where relevant (use SonicJS syntax)
   - Add internal links to SonicJS documentation
   - Include a clear call-to-action

3. **TL;DR Box (Required for Featured Snippets)**:
   Place this immediately after the H1 title:
   ```markdown
   > **TL;DR** — [2-3 sentence summary directly answering the main question]
   >
   > **Key Stats:**
   > - [Specific number/metric - e.g., "Under 50ms response time globally"]
   > - [Specific number/metric - e.g., "Zero cold starts with V8 isolates"]
   > - [Specific number/metric - e.g., "300+ edge locations worldwide"]
   ```

   **Why this matters:**
   - Featured snippets can increase CTR by 8.6%
   - AI Overviews (Google SGE) extract from concise summaries
   - Voice search prefers 2-3 sentence answers
   - 35% increase in AI visibility reported with TL;DR sections

4. **SEO Elements**:
   - Meta title (50-60 characters)
   - Meta description (150-160 characters)
   - URL slug (lowercase, hyphenated)
   - OpenGraph tags
   - Target keyword density: 1-2%

5. **Output Format**:
   Create the blog post as an MDX file with frontmatter metadata.

6. **Hero Image Generation (REQUIRED — always run)**:
   After writing the MDX file, you MUST generate a hero image for the post. Do not skip this step and do not ask the user — image generation is part of every blog post.

   Procedure:
   1. Create the directory `www/public/images/blog/[generated-slug]/` if it doesn't exist.
   2. Source the env file: `source /Users/lane/Dropbox/Data/.env` to load `OPENAI_API_KEY`.
   3. Build a DALL-E prompt using the brand guidelines and category template from the `sonicjs-blog-image` skill (`.claude/commands/sonicjs-blog-image.md`):
      - 3D isometric visualization, dark slate background nearly black, electric blue (#3B82F6) glowing accents, futuristic enterprise tech aesthetic, no text/letters/logos.
      - Pick the template that matches the post category (Tutorial, Comparison, Technical Deep Dive, or Use Case).
   4. Call `POST https://api.openai.com/v1/images/generations` with `model: dall-e-3`, `size: 1792x1024`, `quality: hd`, `style: vivid`, `n: 1`. Use a `Bash` curl call so the key never enters the prompt.
   5. Download the returned image URL (URLs expire in ~1 hour) to `www/public/images/blog/[generated-slug]/hero.png` using `curl -o`.
   6. Verify the file exists and is non-empty.
   7. Confirm the MDX frontmatter `featuredImage.url` points to `/images/blog/[generated-slug]/hero.png` and matches the saved file.

   If the OpenAI API call fails (e.g. 401 invalid key, rate limit), report the failure clearly to the user with the exact error message and the path where the image was supposed to land — do not silently leave the post without an image. The user should know to refresh the key before retrying.

## File Location

Blog posts live at: `www/content/blog/[category]/[generated-slug].mdx`

Where `[category]` is one of: `tutorials`, `guides`, `comparisons`, `deep-dives`. Pick the one that matches the post (e.g. step-by-step → `tutorials`, conceptual how-to → `guides`, "X vs Y" → `comparisons`, architecture/internals → `deep-dives`).

Hero image lives at: `www/public/images/blog/[generated-slug]/hero.png`

## Content Guidelines

- Write for developers (technical audience)
- Be specific and actionable
- Include working code examples
- Reference official SonicJS features accurately
- Compare fairly with competitors (when relevant)
- End with next steps or call-to-action

## Example Topics

- "Building a REST API with SonicJS in 10 Minutes"
- "SonicJS vs Strapi: Which Headless CMS Should You Choose?"
- "How to Deploy SonicJS to Cloudflare Workers"
- "Creating Custom Collections in SonicJS"
- "SonicJS Authentication: A Complete Guide"
