#include "mcx/h2.hpp"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <map>
#include <nghttp2/nghttp2.h>
#include <poll.h>
#include <sys/socket.h>

namespace mcx::h2 {
namespace {
struct Connection {
  struct Stream {
    Request request;
    std::string status;
    Response response;
    std::size_t sent = 0;
  };
  int fd;
  const Handler &handle;
  std::map<int32_t, Stream> streams;
  nghttp2_session *session = nullptr;

  static nghttp2_nv header(const std::string &name, const std::string &value) {
    return {reinterpret_cast<uint8_t *>(const_cast<char *>(name.data())),
            reinterpret_cast<uint8_t *>(const_cast<char *>(value.data())), name.size(), value.size(),
            NGHTTP2_NV_FLAG_NONE};
  }
  static int on_begin_headers(nghttp2_session *, const nghttp2_frame *frame, void *self) {
    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST)
      static_cast<Connection *>(self)->streams[frame->hd.stream_id];
    return 0;
  }
  static int on_header(nghttp2_session *, const nghttp2_frame *frame, const uint8_t *name, size_t namelen,
                       const uint8_t *value, size_t valuelen, uint8_t, void *self) {
    auto &streams = static_cast<Connection *>(self)->streams;
    const auto it = streams.find(frame->hd.stream_id);
    if (it == streams.end()) return 0;
    const std::string_view n(reinterpret_cast<const char *>(name), namelen);
    const std::string v(reinterpret_cast<const char *>(value), valuelen);
    if (n == ":method") it->second.request.method = v;
    else if (n == ":path") it->second.request.path = v;
    return 0;
  }
  static int on_data(nghttp2_session *, uint8_t, int32_t stream_id, const uint8_t *data, size_t len, void *self) {
    auto &streams = static_cast<Connection *>(self)->streams;
    if (const auto it = streams.find(stream_id); it != streams.end()) {
      if (it->second.request.body.size() + len > 1 << 20) return NGHTTP2_ERR_CALLBACK_FAILURE;
      it->second.request.body.append(reinterpret_cast<const char *>(data), len);
    }
    return 0;
  }
  static ssize_t read_body(nghttp2_session *, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *flags,
                           nghttp2_data_source *, void *self) {
    auto &streams = static_cast<Connection *>(self)->streams;
    const auto it = streams.find(stream_id);
    if (it == streams.end()) {
      *flags |= NGHTTP2_DATA_FLAG_EOF;
      return 0;
    }
    auto &s = it->second;
    const auto n = std::min(length, s.response.body.size() - s.sent);
    std::memcpy(buf, s.response.body.data() + s.sent, n);
    s.sent += n;
    if (s.sent == s.response.body.size()) *flags |= NGHTTP2_DATA_FLAG_EOF;
    return static_cast<ssize_t>(n);
  }
  static int on_frame(nghttp2_session *session, const nghttp2_frame *frame, void *self) {
    auto *c = static_cast<Connection *>(self);
    if ((frame->hd.type != NGHTTP2_HEADERS && frame->hd.type != NGHTTP2_DATA) ||
        !(frame->hd.flags & NGHTTP2_FLAG_END_STREAM))
      return 0;
    const auto it = c->streams.find(frame->hd.stream_id);
    if (it == c->streams.end()) return 0;
    auto &s = it->second;
    s.response = c->handle(s.request);
    s.status = std::to_string(s.response.status);
    s.response.headers.emplace_back("content-length", std::to_string(s.response.body.size()));
    static const std::string status_name = ":status";
    std::vector<nghttp2_nv> headers{header(status_name, s.status)};
    for (const auto &[name, value] : s.response.headers) headers.push_back(header(name, value));
    nghttp2_data_provider body{};
    body.read_callback = read_body;
    nghttp2_submit_response(session, frame->hd.stream_id, headers.data(), headers.size(),
                            s.response.body.empty() ? nullptr : &body);
    return 0;
  }
  static int on_close(nghttp2_session *, int32_t stream_id, uint32_t, void *self) {
    static_cast<Connection *>(self)->streams.erase(stream_id);
    return 0;
  }

  bool flush() {
    for (;;) {
      const uint8_t *out = nullptr;
      const auto n = nghttp2_session_mem_send(session, &out);
      if (n < 0) return false;
      if (n == 0) return true;
      for (ssize_t sent = 0; sent < n;) {
        const auto w = ::send(fd, out + sent, static_cast<std::size_t>(n - sent), MSG_NOSIGNAL);
        if (w <= 0) return false;
        sent += w;
      }
    }
  }
};
}  // namespace

bool serve(int fd, std::string_view received, const Handler &handle, const std::function<bool()> &stopping,
           int idle_ms) {
  if (!received.starts_with(preface)) return false;
  Connection c{fd, handle, {}, nullptr};
  nghttp2_session_callbacks *callbacks = nullptr;
  nghttp2_session_callbacks_new(&callbacks);
  nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, Connection::on_begin_headers);
  nghttp2_session_callbacks_set_on_header_callback(callbacks, Connection::on_header);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, Connection::on_data);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, Connection::on_frame);
  nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, Connection::on_close);
  nghttp2_session_server_new(&c.session, callbacks, &c);
  nghttp2_session_callbacks_del(callbacks);
  const nghttp2_settings_entry settings[] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 16}};
  nghttp2_submit_settings(c.session, NGHTTP2_FLAG_NONE, settings, 1);
  bool ok = nghttp2_session_mem_recv(c.session, reinterpret_cast<const uint8_t *>(received.data()), received.size()) >=
                0 &&
            c.flush();
  int idle = 0;
  char buffer[4096];
  while (ok && (nghttp2_session_want_read(c.session) || nghttp2_session_want_write(c.session))) {
    if (stopping() || idle >= idle_ms) {
      nghttp2_session_terminate_session(c.session, NGHTTP2_NO_ERROR);
      c.flush();
      break;
    }
    pollfd p{fd, POLLIN, 0};
    const int ready = ::poll(&p, 1, 100);
    if (ready < 0) break;
    if (ready == 0) {
      idle += c.streams.empty() ? 100 : 0;
      continue;
    }
    const auto n = ::recv(fd, buffer, sizeof buffer, 0);
    if (n <= 0) break;
    idle = 0;
    ok = nghttp2_session_mem_recv(c.session, reinterpret_cast<const uint8_t *>(buffer), static_cast<std::size_t>(n)) >=
             0 &&
         c.flush();
  }
  nghttp2_session_del(c.session);
  return true;
}
}  // namespace mcx::h2
