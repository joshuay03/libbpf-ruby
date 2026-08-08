# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "libbpf-ruby"

require "minitest/autorun"

BPF_OBJECT_PATH = File.expand_path("fixtures/test_program.bpf.o", __dir__)

unless File.directory?("/sys/kernel/tracing/events")
  system("mount", "-t", "tracefs", "tracefs", "/sys/kernel/tracing", exception: false)
end
