// @ts-nocheck
import { HtmlString, time_html } from "./templates.tsx";

export type Doc = { html: string };

export type RenderCtx = {
  date?: Date;
  summary?: string;
  title?: string;
};

/**
 * Parse Markdown to HTML by invoking pandoc.
 *
 * Requirements at runtime:
 * - pandoc must be installed and available in PATH.
 * - deno run must have --allow-run and --allow-write=./out permissions.
 */
export function parse(source: string): Doc {
  // Preprocess Obsidian syntax
  source = preprocessObsidian(source);

  ensureTmpDir();
  const inputPath = Deno.makeTempFileSync({ dir: "./out/tmp", suffix: ".md" });

  try {
    Deno.writeTextFileSync(inputPath, source);

    const cmd = new Deno.Command("pandoc", {
      args: [
        "-f",
        "gfm+fenced_divs", // GitHub-Flavored Markdown input
        "-t",
        "html", // HTML fragment output
        "--mathjax", // preserve math for client-side MathJax
        "--highlight-style",
        "pygments", // server-side syntax highlighting
        inputPath,
      ],
      stdout: "piped",
      stderr: "piped",
    });

    let out: Deno.CommandOutput;
    try {
      out = cmd.outputSync();
    } catch (e) {
      if (e instanceof Deno.errors.NotFound) {
        throw new Error(
          "pandoc not found on PATH. Please install pandoc to enable Markdown rendering.",
        );
      }
      throw e;
    }

    const stdout = decode(out.stdout);
    const stderr = decode(out.stderr);
    if (!out.success) {
      throw new Error(`pandoc failed: ${stderr.trim()}`);
    }

    return { html: stdout };
  } finally {
    try {
      Deno.removeSync(inputPath);
    } catch {
      // ignore cleanup errors
    }
  }
}

/**
 * Post-process pandoc HTML:
 * - Extract title (first <h1>) and summary (first <p>).
 * - If ctx.date is provided: wrap first <h1> into <header> with date.
 * - Anchor H2+ headings by wrapping content with <a href="#id">...</a> if id exists.
 */
export function render(doc: Doc, ctx: RenderCtx): HtmlString {
  let html = doc.html;

  // Extract the first <h1> as title; wrap with header if date present.
  {
    const h1Rx = /<h1(\s+[^>]*)?>([\s\S]*?)<\/h1>/i;
    const m = html.match(h1Rx);
    if (m) {
      const h1Attrs = m[1] ?? "";
      const h1Inner = m[2] ?? "";
      const titleText = stripHtml(h1Inner).trim();
      if (!ctx.title && titleText) ctx.title = titleText;

      if (ctx.date) {
        const header = [
          "<header>",
          `  <h1${h1Attrs}>${h1Inner}</h1>`,
          `  ${time_html(ctx.date, "meta")}`,
          "</header>",
        ].join("\n");
        html = html.replace(h1Rx, header);
      }
    }
  }

  // Extract summary from the first paragraph if not already set.
  if (!ctx.summary) {
    const pRx = /<p>([\s\S]*?)<\/p>/i;
    const m = html.match(pRx);
    if (m) {
      const text = stripHtml(m[1]).trim();
      if (text) ctx.summary = text;
    }
  }

  // Anchor H2..H6 headings if they have an id attribute.
  html = html.replace(
    /<h([2-6])([^>]*)>([\s\S]*?)<\/h\1>/gi,
    (_all, level: string, attrs: string, inner: string) => {
      const id = findId(attrs);
      if (!id) return `<h${level}${attrs}>${inner}</h${level}>`;
      return `<h${level}${attrs}><a href="#${id}">${inner}</a></h${level}>`;
    },
  );

  return new HtmlString(html);
}

/* Utilities */

function ensureTmpDir() {
  try {
    Deno.mkdirSync("./out/tmp", { recursive: true });
  } catch {
    // ignore
  }
}

const decoder = new TextDecoder();
function decode(buf: Uint8Array): string {
  return decoder.decode(buf);
}

function stripHtml(s: string): string {
  const withoutTags = s.replace(/<[^>]*>/g, "");
  return withoutTags
    .replace(/&nbsp;/g, " ")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}

function findId(attrs: string): string | null {
  const m = attrs.match(/\sid="([^"]+)"/i);
  return m ? m[1] : null;
}

function processWikilinks(line: string): string {
  return line.replace(/\[\[([^\]|]+)(\|[^\]]+)?\]\]/g, (match, link, alt) => {
    const display = alt ? alt.slice(1) : link;
    // For now, just return the display text, since links may not resolve in static site
    return display;
  });
}

/**
 * Preprocess Obsidian-specific syntax to standard Markdown/HTML.
 */
function preprocessObsidian(source: string): string {
  const lines = source.split('\n');
  const result: string[] = [];
  let inCallout = false;
  let calloutType = '';
  let calloutTitle = '';
  const calloutQuote: string[] = [];
  const calloutNotes: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Check for callout start: > [!type] or > [!type|meta]
    const calloutMatch = line.match(/^>\s*\[!([^\]|]+)(\|[^\]]*)?\]\s*(.*)$/);
    if (calloutMatch) {
      if (inCallout) {
        // Close previous callout
        result.push(buildCalloutHTML(calloutType, calloutTitle, calloutQuote, calloutNotes));
        calloutQuote.length = 0;
        calloutNotes.length = 0;
      }
      inCallout = true;
      calloutType = calloutMatch[1];
      const remaining = calloutMatch[3];
      calloutTitle = remaining ? processWikilinks(remaining) : '';
      continue;
    }

    // Check for continuation of callout: > content
    const calloutContinueMatch = line.match(/^>\s*(.*)$/);
    if (inCallout && calloutContinueMatch) {
      const content = calloutContinueMatch[1];
      if (content.startsWith('>') || content.trim() === '' && calloutQuote.length > 0) {
        calloutQuote.push(line);
      } else {
        calloutNotes.push(content);
      }
      continue;
    }

    // If we were in a callout, close it
    if (inCallout) {
      result.push(buildCalloutHTML(calloutType, calloutTitle, calloutQuote, calloutNotes));
      inCallout = false;
      calloutQuote.length = 0;
      calloutNotes.length = 0;
    }

    // Handle wikilinks: [[link|text]] or [[link]]
    const processedLine = processWikilinks(line);

    result.push(processedLine);
  }

  // Close any remaining callout
  if (inCallout) {
    result.push(buildCalloutHTML(calloutType, calloutTitle, calloutQuote, calloutNotes));
  }

  return result.join('\n');
}

function buildCalloutHTML(type: string, title: string, quote: string[], notes: string[]): string {
  let md = `::: {.callout .callout-${type.toLowerCase()}}\n`;
  if (title) md += `**${title}**\n\n`;
  if (quote.length) md += `**PDF Quote:**\n\n${quote.join('\n')}\n\n`;
  if (notes.length) md += `**Notes:**\n\n${notes.map(processWikilinks).join('\n')}\n\n`;
  md += ':::\n';
  return md;
}
