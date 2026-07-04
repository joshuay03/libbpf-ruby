# frozen_string_literal: true

require "test_helper"

require "socket"

class TestLibBPFRuby < Minitest::Test
  def setup
    @object = LibBPFRuby::Object.new(BPF_OBJECT_PATH)
    @map_fd = @object.map_fd("test_map")
    @sockmap_fd = @object.map_fd("test_sockmap")
    @program_fd = @object.program_fd("test_program")
  end

  def teardown
    @object.close
  end

  def test_version
    refute_nil LibBPFRuby::VERSION
  end

  def test_map_update
    assert LibBPFRuby.map_update(@map_fd, [0].pack("L"), [42].pack("L"))
  end

  def test_sockmap_update
    socket = build_reuseport_socket
    assert LibBPFRuby.sockmap_update(@sockmap_fd, [0].pack("L"), socket)
  ensure
    socket&.close
  end

  def test_map_lookup
    LibBPFRuby.map_update(@map_fd, [0].pack("L"), [42].pack("L"))
    assert_equal 42, LibBPFRuby.map_lookup(@map_fd, [0].pack("L"), 4).unpack1("L")
  end

  def test_map_lookup_returns_nil_for_missing_key
    assert_nil LibBPFRuby.map_lookup(@map_fd, [999].pack("L"), 4)
  end

  def test_attach_reuseport
    socket = build_reuseport_socket
    assert LibBPFRuby.attach_reuseport(socket, @program_fd)
  ensure
    socket&.close
  end

  private

  def build_reuseport_socket
    socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
    socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, true)
    socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, true)
    socket.bind(Socket.pack_sockaddr_in(0, "127.0.0.1"))
    socket.listen(1)
    socket
  end
end
