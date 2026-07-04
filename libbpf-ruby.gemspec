# frozen_string_literal: true

require_relative "lib/libbpf-ruby/version"

Gem::Specification.new do |spec|
  spec.name = "libbpf-ruby"
  spec.version = LibBPFRuby::VERSION
  spec.authors = ["Joshua Young"]
  spec.email = ["djry1999@gmail.com"]

  spec.summary = "libbpf wrapper for Ruby"
  spec.homepage = "https://github.com/joshuay03/libbpf-ruby"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.3.0"

  spec.metadata["documentation_uri"] = "https://joshuay03.github.io/libbpf-ruby/"
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"

  spec.files = Dir["lib/**/*.rb", "ext/**/*.{rb,c,h}", "**/*.{gemspec,md,txt}"]
  spec.require_paths = ["lib"]
  spec.extensions = ["ext/libbpf_ruby/extconf.rb"]
end
