# frozen_string_literal: true

require "test_helper"

class TestObject < Minitest::Test
  def setup
    @object = LibBPFRuby::Object.new(BPF_OBJECT_PATH)
  end

  def teardown
    @object.close
  end

  def test_new
    assert_kind_of LibBPFRuby::Object, @object
  end

  def test_new_raises_for_invalid_path
    assert_raises RuntimeError do
      LibBPFRuby::Object.new("nonexistent.bpf.o")
    end
  end

  def test_program_fd
    assert_kind_of Integer, @object.program_fd("test_program")
  end

  def test_program_fd_raises_for_unknown_name
    assert_raises RuntimeError do
      @object.program_fd("nonexistent")
    end
  end

  def test_map_fd
    assert_kind_of Integer, @object.map_fd("test_map")
  end

  def test_map_fd_raises_for_unknown_name
    assert_raises RuntimeError do
      @object.map_fd("nonexistent")
    end
  end

  def test_close
    assert_nil @object.close
  end
end
