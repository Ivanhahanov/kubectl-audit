# Docs site (GitHub Pages)

This directory is a self-contained Jekyll site (custom layout, no themes/Gemfile needed — GitHub
Pages builds plain Jekyll like this automatically). To publish it:

1. Push this repo to GitHub.
2. In the repo, go to **Settings → Pages**.
3. Under **Build and deployment**, set **Source** to "Deploy from a branch".
4. Set **Branch** to `main` (or whichever default branch) and folder to **`/docs`**.
5. Save. The site will be live at `https://<org>.github.io/<repo>/` within a minute or two.

`_config.yml` already sets `baseurl`/`url` for `ivanhahanov/kubectl-audit`; update those two
values (and the `site.repository` links used throughout the pages) if you fork or rename the repo.

## Local preview (optional)

Requires Ruby + Bundler:

```sh
cd docs
gem install bundler jekyll
bundle init && bundle add jekyll
bundle exec jekyll serve
```

Then open `http://localhost:4000/kubectl-audit/`.
