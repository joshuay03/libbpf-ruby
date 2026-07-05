# LibBPFRuby

![Version](https://img.shields.io/gem/v/libbpf-ruby)
![Build](https://badge.buildkite.com/c7ce68e58e1f481f8b62f452756532c75983ec5aeafb151dd3.svg)

[`libbpf`](https://github.com/libbpf/libbpf) wrapper for Ruby.

**Docs:** https://joshuay03.github.io/libbpf-ruby

## Installation

Install the gem and add to the application's Gemfile by executing:

```bash
bundle add libbpf-ruby
```

If bundler is not being used to manage dependencies, install the gem by executing:

```bash
gem install libbpf-ruby
```

The native extension links against [`libbpf`](https://github.com/libbpf/libbpf), which is Linux-only. On unsupported platforms the gem installs without compiling the extension; requiring it at runtime raises `LoadError`.

## Usage

```ruby
# frozen_string_literal: true

require "libbpf-ruby"
require "socket"

object = LibBPFRuby::Object.new("my_program.bpf.o")

program_fd = object.program_fd("my_program")
map_fd = object.map_fd("my_map")

LibBPFRuby.map_update(map_fd, [0].pack("L"), [42].pack("L"))

listening_socket = TCPServer.new(3000)
LibBPFRuby.attach_reuseport(listening_socket, program_fd)
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `bundle exec rake` to compile native extensions and run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

If you're on macOS (or any non-Linux host), `bin/dev` builds and drops you into a Docker image with `libbpf-dev`, `clang`, and Ruby preinstalled, mounting the repo at `/workspace`. Run `bin/dev` for an interactive shell, or `bin/dev bundle exec rake` to run the full build and test cycle in one shot.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/joshuay03/libbpf-ruby. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/joshuay03/libbpf-ruby/blob/main/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the LibBPFRuby project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/joshuay03/libbpf-ruby/blob/main/CODE_OF_CONDUCT.md).
