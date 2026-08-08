# frozen_string_literal: true

require "test_helper"

class TestLibBPFRuby < Minitest::Test
  def test_version
    refute_nil LibBPFRuby::VERSION
  end
end
