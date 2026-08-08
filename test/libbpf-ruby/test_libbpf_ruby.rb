# frozen_string_literal: true

require "test_helper"

class TestLibBPFRuby < Minitest::Test
  def test_version
    refute_nil LibBPFRuby::VERSION
  end

  def test_ractor_safe
    ractor = Ractor.new(BPF_OBJECT_PATH) do |path|
      object = LibBPFRuby::Object.new(path)
      fd = object.program_fd("test_program")
      object.close
      fd
    end
    assert_kind_of Integer, (ractor.respond_to?(:value) ? ractor.value : ractor.take)
  end
end
