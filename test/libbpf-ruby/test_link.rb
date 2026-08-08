# frozen_string_literal: true

require "test_helper"

class TestLink < Minitest::Test
  parallelize_me!

  def setup
    @object = LibBPFRuby::Object.new(BPF_OBJECT_PATH)
    @program = @object.program("test_tracepoint_program")
    @link = @program.attach
  end

  def teardown
    @link&.detach
    @object.close
  end

  def test_fd
    assert_kind_of Integer, @link.fd
  end

  def test_detach
    assert_nil @link.detach
  end

  def test_fd_raises_for_detached_link
    @link.detach
    assert_raises RuntimeError do
      @link.fd
    end
  end
end
