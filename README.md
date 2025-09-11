# AN HA's Blog

A technical blog focused on systems programming, operating systems, and distributed systems.

## Structure

This blog is built using the [matklad.github.io](https://github.com/matklad/matklad.github.io) template with Deno and djot markup.

### Content Organization

- **Regular Posts** (`content/posts/`): Technical articles, tutorials, and general programming content
- **Research Papers** (`content/research-papers/`): Summaries and analyses of academic papers
- **About** (`content/about.dj`): Personal information and blog description

### Navigation

The blog includes two main sections:
- **Home**: Latest posts from all categories
- **Research Papers**: Dedicated section for research paper summaries

## Development

### Prerequisites

- [Deno](https://deno.land/) for the build system

### Commands

```console
$ deno task build
$ deno task watch
$ deno task touch my-new-post-slug
```

### Adding Content

#### Regular Blog Posts

Create files in `content/posts/` with the format `YYYY-MM-DD-slug.dj`:

```djot
# Your Post Title

Your content here using djot markup...
```

#### Research Papers

Create files in `content/research-papers/` with the same format. These will appear in the dedicated Research Papers section.

### Djot Markup

This blog uses [djot](https://djot.net/) markup language, which is similar to Markdown but with some differences:

- Links: `https://example.com[link text]` instead of `[link text](https://example.com)`
- Images: `/path/to/image.png[alt text]` instead of `![alt text](/path/to/image.png)`

## Migration Notes

This blog was migrated from Jekyll. The original content structure has been preserved:

- Original `_notes/` content has been converted to djot format
- Posts are organized by type (regular posts vs research papers)
- Assets have been moved to `content/assets/`

## Deployment

The built site is in `out/www/` and can be deployed to any static hosting service.

## License

Code samples on this blog are dual licensed under MIT OR Apache-2.0.
