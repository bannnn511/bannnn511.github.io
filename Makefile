# Makefile for Jekyll site

.PHONY: build serve clean install update deploy

# Variables
JEKYLL_ENV ?= development
BASE_URL ?= ""

# Install dependencies
install:
	gem install bundler
	bundle install

# Update dependencies
update:
	bundle update

# Build the site
build:
	JEKYLL_ENV=$(JEKYLL_ENV) bundle exec jekyll build --baseurl "$(BASE_URL)"

# Serve the site locally
serve:
	bundle exec jekyll serve --livereload

# Clean built files
clean:
	bundle exec jekyll clean

# Deploy to GitHub Pages (manually triggers GitHub Actions workflow)
deploy:
	@echo "Triggering GitHub Actions workflow for deployment..."
	git push origin $(shell git rev-parse --abbrev-ref HEAD)

# Build for production
production-build:
	$(MAKE) build JEKYLL_ENV=production