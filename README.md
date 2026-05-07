# Blog

View the blog here [https://0xEcto.github.io/](https://0xEcto.github.io/).

> [!WARNING]
> When adding code blocks with multiple curly braces within it, gitpages may not create the page correctly and the build results in an error. In Liquid (the templating engine used by Jekyll), curly braces `{{ }}` are used to denote variables or expressions that should be processed. When these braces appear in the content, Liquid tries to interpret them, which leads to syntax errors if they're part of a code block rather than a Liquid template. To fix - escape these curly braces by using the raw tag in Jekyll, which tells Liquid to ignore the content inside these tags. Modify post to wrap the code block within `{% raw %}` and `{% endraw %}` tags.

## Local Development

### Prerequisites

- [RubyInstaller for Windows](https://rubyinstaller.org/downloads/) — download the **Ruby+Devkit** version (3.x or later)
  - During install: check **"Add Ruby executables to your PATH"**
  - On the final screen: check **"Run 'ridk install'"**, then select option **3** (MSYS2 and MINGW toolchain)

### First-time setup

```bash
gem install jekyll bundler
bundle install
```

### Running locally

```bash
bundle exec jekyll serve
```

Then open [http://localhost:4000](http://localhost:4000) in your browser.

The server auto-reloads on file saves. If you change `_config.yml`, restart the server.

### Notes

- Ruby 4.0+ requires `bigdecimal`, `tzinfo`, and `tzinfo-data` to be listed explicitly in the `Gemfile` — these are already included
- `wdm` gem is included for file watching support on Windows