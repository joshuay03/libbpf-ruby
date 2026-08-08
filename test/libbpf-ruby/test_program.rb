# frozen_string_literal: true

require "test_helper"

class TestProgram < Minitest::Test
  parallelize_me!

  def setup
    @object = LibBPFRuby::Object.new(BPF_OBJECT_PATH)
    @program = @object.program("test_tracepoint_program")
  end

  def teardown
    @object.close
  end

  def test_fd
    assert_kind_of Integer, @program.fd
  end

  def test_name
    assert_equal "test_tracepoint_program", @program.name
  end

  def test_attach
    link = @program.attach
    assert_kind_of LibBPFRuby::Link, link
  ensure
    link&.detach
  end

  def test_fd_raises_for_closed_object
    @object.close
    assert_raises RuntimeError do
      @program.fd
    end
  end
end
