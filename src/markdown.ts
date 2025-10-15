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
  ensureTmpDir();
  const inputPath = Deno.makeTempFileSync({ dir: "./out/tmp", suffix: ".md" });

  try {
    Deno.writeTextFileSync(inputPath, source);

    const cmd = new Deno.Command("pandoc", {
      args: [
        "-f",
        "gfm", // GitHub-Flavored Markdown input
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
