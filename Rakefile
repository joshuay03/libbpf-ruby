# frozen_string_literal: true

require "bundler/gem_tasks"
require "minitest/test_task"
require "rake/extensiontask"

GEMSPEC = Gem::Specification.load("libbpf-ruby.gemspec")

Minitest::TestTask.create

Rake::ExtensionTask.new("libbpf_ruby", GEMSPEC) do |ext|
  ext.lib_dir = "lib/libbpf_ruby"
end

namespace :fixtures do
  task :compile do
    arch = `uname -m`.chomp
    Dir["test/fixtures/*.bpf.c"].each do |source|
      object = source.sub(/\.c\z/, ".o")
      sh "clang -O2 -g -target bpf -I/usr/include/#{arch}-linux-gnu -c #{source} -o #{object}"
    end
  end
end

namespace :rbs do
  task :generate do
    puts
    sh "rm -rf sig && rbs-inline --opt-out --output lib && echo"
  end
end

task build: %i[compile rbs:generate]
task default: %i[clobber compile rbs:generate fixtures:compile test]
