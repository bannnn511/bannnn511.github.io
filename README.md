# AN HA's Blog

A technical blog focused on systems programming, operating systems, and distributed systems.

## Structure

This blog is built using the [matklad.github.io](https://github.com/matklad/matklad.github.io) template with Deno and Markdown (GFM).

### Content Organization

- **Regular Posts** (`content/posts/`): Technical articles, tutorials, and general programming content
- **Research Papers** (`content/research-papers/`): Summaries and analyses of academic papers
- **About** (`content/about.md`): Personal information and blog description

### Navigation

The blog includes two main sections:
- **Home**: Latest posts from all categories
- **Research Papers**: Dedicated section for research paper summaries

## Development

### Prerequisites

- [Deno](https://deno.land/) for the build system
- [Pandoc](https://pandoc.org/) to render Markdown to HTML (must be installed and on PATH)

### Commands

```console
$ deno task build
$ deno task watch
$ deno task touch my-new-post-slug
$ python3 -m http.server 3001 --directory out/www
```

### Adding Content

#### Regular Blog Posts

Create files in `content/posts/` with the format `YYYY-MM-DD-slug.md`:

```markdown
# Your Post Title

Your content here using Markdown...
```

#### Research Papers

Create files in `content/research-papers/` with the same format. These will appear in the dedicated Research Papers section.

### Markdown

This blog uses GitHub-Flavored Markdown (GFM).

- Links: `[link text](https://example.com)`
- Images: `![alt text](/path/to/image.png)`

## Migration Notes

This blog was migrated from Jekyll. The original content structure has been preserved:

- Original `_notes/` content has been converted to Markdown format
- Posts are organized by type (regular posts vs research papers)
- Assets have been moved to `content/assets/`

## Deployment

The built site is in `out/www/` and can be deployed to any static hosting service.

## License

Code samples on this blog are dual licensed under MIT OR Apache-2.0.
