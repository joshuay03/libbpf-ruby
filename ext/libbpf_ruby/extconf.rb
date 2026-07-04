# frozen_string_literal: true

require "mkmf"

abort "libbpf-ruby requires Linux" unless RUBY_PLATFORM.include?("linux")
abort "libbpf-ruby requires libbpf (install libbpf-dev)" unless have_library("bpf")
abort "libbpf-ruby requires libbpf headers (install libbpf-dev)" unless have_header("bpf/libbpf.h")

append_cflags("-fvisibility=hidden")
create_makefile("libbpf_ruby/libbpf_ruby")
