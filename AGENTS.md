# Agents Documentation

This document provides ground truth for commands, styles, and structure used in this project. Agents should refer to this file for consistent behavior.

## Project Overview

This is a static site generator for bannnn511.github.io, built with Deno. It generates HTML from Markdown files in the `content/` directory.

## Directory Structure

- `content/`: Source Markdown files
  - `posts/`: Blog posts, named as `YYYY-MM-DD-slug.md`
  - `research-papers/`: Research paper notes, named as `YYYY-MM-DD-slug.md`
  - `about.md`, `resume.md`, `links.md`, `style.md`: Static pages
  - `assets/`: Images and other assets
- `src/`: Deno TypeScript source code
- `out/www/`: Generated HTML output

## Build Commands

- Build site: `deno run --allow-all src/main.ts build`
- Watch for changes: `deno run --allow-all src/main.ts watch [--filter=<path>]`
- Spell check: `deno run --allow-all src/main.ts spell`
- Create new post: `deno run --allow-all src/main.ts touch <slug>` (creates `content/posts/YYYY-MM-DD-<slug>.md`)

## Markdown Format

- Use GitHub-Flavored Markdown (GFM)
- Titles are extracted from the first `# Heading`
- Research papers must have date prefix in filename: `YYYY-MM-DD-slug.md`
- Use pandoc for rendering, with MathJax support and Pygments highlighting

## File Naming Conventions

- Posts: `YYYY-MM-DD-slug.md` in `content/posts/`
- Research papers: `YYYY-MM-DD-slug.md` in `content/research-papers/`
- Slugs: lowercase, hyphen-separated

## Dependencies

- Deno runtime
- Pandoc for Markdown processing
- Git for version control

## Common Tasks

- To add a new post: Run touch command, edit the created file
- To update research paper: Ensure filename follows date-slug.md pattern, add # Title heading
- To deploy: Commit changes, push to GitHub (GitHub Actions handles deployment)

## Styles and Structure

- Concise, direct communication
- Use absolute paths for file operations
- Prefer specific tools (Grep, Read) over broad searches
- Format code after edits
- Treat AGENTS.md as authoritative for commands
