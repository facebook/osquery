/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/logger.h>
#include <osquery/remote/http_client.h>

#include <boost/asio/connect.hpp>

namespace osquery {
namespace http {

const std::string kHTTPSDefaultPort{"443"};
const std::string kHTTPDefaultPort{"80"};
const std::string kProxyDefaultPort{"3128"};

const long kSSLShortReadError{0x140000dbL};

void Client::callNetworkOperation(std::function<void()> callback) {
  if (client_options_.timeout_) {
    timer_.async_wait(
        std::bind(&Client::timeoutHandler, this, std::placeholders::_1));
  }

  callback();

  {
    boost::system::error_code rc;
    ioc_.run(rc);
    ioc_.reset();
    if (rc) {
      ec_ = rc;
    }
  }
}

void Client::postResponseHandler(boost::system::error_code const& ec) {
  if ((ec.category() == boost::asio::error::ssl_category) &&
      (ec.value() == kSSLShortReadError)) {
    // Ignoring short read error, set ec_ to success.
    ec_.clear();
    // close connection for security reason.
    LOG(INFO) << "SSL SHORT_READ_ERROR: http_client closing socket";
    closeSocket();
  } else if (ec_ != boost::asio::error::timed_out) {
    ec_ = ec;
  }
}

void Client::closeSocket() {
  if (sock_.is_open()) {
    boost::system::error_code rc;
    sock_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, rc);
    sock_.close(rc);
  }
}

void Client::timeoutHandler(boost::system::error_code const& ec) {
  if (!ec) {
    closeSocket();
    ec_ = boost::asio::error::make_error_code(boost::asio::error::timed_out);
  }
}

void Client::connectHandler(boost::system::error_code const & ec,
                            boost::asio::ip::tcp::endpoint const&) {
  if (client_options_.timeout_) {
    timer_.cancel();
  }

  if (ec_ != boost::asio::error::timed_out) {
    ec_ = ec;
  }
}

void Client::resolveHandler(
    boost::system::error_code const& ec,
    boost::asio::ip::tcp::resolver::results_type results) {
  if (!ec) {
    boost::asio::async_connect(sock_,
                               results,
                               std::bind(&Client::connectHandler,
                                         this,
                                         std::placeholders::_1,
                                         std::placeholders::_2));
  } else {
    if (client_options_.timeout_) {
      timer_.cancel();
    }

    if (ec_ != boost::asio::error::timed_out) {
      ec_ = ec;
    }
  }
}

void Client::handshakeHandler(boost::system::error_code const& ec) {
  if (client_options_.timeout_) {
    timer_.cancel();
  }

  if (ec_ != boost::asio::error::timed_out) {
    ec_ = ec;
  }
}

void Client::writeHandler(boost::system::error_code const& ec, size_t) {
  if (client_options_.timeout_) {
    timer_.cancel();
  }

  if (ec_ != boost::asio::error::timed_out) {
    ec_ = ec;
  }
}

void Client::readHandler(boost::system::error_code const& ec, size_t) {
  if (client_options_.timeout_) {
    timer_.cancel();
  }
  postResponseHandler(ec);
}

void Client::createConnection() {
  std::string port = (client_options_.proxy_hostname_)
                         ? kProxyDefaultPort
                         : *client_options_.remote_port_;

  std::string connect_host = (client_options_.proxy_hostname_)
                                 ? *client_options_.proxy_hostname_
                                 : *client_options_.remote_hostname_;

  std::size_t pos;
  if ((pos = connect_host.find(":")) != std::string::npos) {
    port = connect_host.substr(pos + 1);
    connect_host = connect_host.substr(0, pos);
  }

  callNetworkOperation([&]() {
    r_.async_resolve(boost::asio::ip::tcp::resolver::query{connect_host, port},
                     std::bind(&Client::resolveHandler,
                               this,
                               std::placeholders::_1,
                               std::placeholders::_2));
  });

  if (ec_) {
    std::string error("Failed to connect to ");
    if (client_options_.proxy_hostname_) {
      error += "proxy host ";
    }
    error += connect_host + ':' + port;
    throw std::system_error(ec_, error);
  }

  if (client_options_.keep_alive_) {
    boost::asio::socket_base::keep_alive option(true);
    sock_.set_option(option);
  }

  if (client_options_.proxy_hostname_) {
    std::string remote_host = *client_options_.remote_hostname_;
    std::string remote_port = *client_options_.remote_port_;

    beast_http_request req;
    req.method(beast_http::verb::connect);
    req.target(remote_host + ':' + remote_port);
    req.version(11);
    req.prepare_payload();

    callNetworkOperation([&]() {
      beast_http::async_write(sock_,
                              req,
                              std::bind(&Client::writeHandler,
                                        this,
                                        std::placeholders::_1,
                                        std::placeholders::_2));
    });

    if (ec_) {
      throw std::system_error(ec_);
    }

    boost::beast::flat_buffer b;
    beast_http_response_parser rp;
    rp.skip(true);

    callNetworkOperation([&]() {
      beast_http::async_read_header(sock_,
                                    b,
                                    rp,
                                    std::bind(&Client::readHandler,
                                              this,
                                              std::placeholders::_1,
                                              std::placeholders::_2));
    });

    if (ec_) {
      throw std::system_error(ec_);
    }

    if (beast_http::to_status_class(rp.get().result()) !=
        beast_http::status_class::successful) {
      throw std::runtime_error(rp.get().reason().data());
    }
  }
}

void Client::encryptConnection() {
  boost::asio::ssl::context ctx{boost::asio::ssl::context::sslv23};

  if (client_options_.always_verify_peer_) {
    ctx.set_verify_mode(boost::asio::ssl::verify_peer);
  } else {
    ctx.set_verify_mode(boost::asio::ssl::verify_none);
  }

  if (client_options_.server_certificate_) {
    ctx.set_verify_mode(boost::asio::ssl::verify_peer);
    ctx.load_verify_file(*client_options_.server_certificate_);
  }

  if (client_options_.verify_path_) {
    ctx.set_verify_mode(boost::asio::ssl::verify_peer);
    ctx.add_verify_path(*client_options_.verify_path_);
  }

  if (client_options_.ciphers_) {
    ::SSL_CTX_set_cipher_list(ctx.native_handle(),
                              client_options_.ciphers_->c_str());
  }

  if (client_options_.ssl_options_) {
    ctx.set_options(client_options_.ssl_options_);
  }

  if (client_options_.client_certificate_file_) {
    ctx.use_certificate_file(*client_options_.client_certificate_file_,
                             boost::asio::ssl::context::pem);
  }

  if (client_options_.client_private_key_file_) {
    ctx.use_private_key_file(*client_options_.client_private_key_file_,
                             boost::asio::ssl::context::pem);
  }

  ssl_sock_ = std::make_shared<ssl_stream>(sock_, ctx);
  if (client_options_.sni_hostname_) {
    ::SSL_set_tlsext_host_name(ssl_sock_->native_handle(),
                               client_options_.sni_hostname_->c_str());
  }

  callNetworkOperation([&]() {
    ssl_sock_->async_handshake(
        boost::asio::ssl::stream_base::client,
        std::bind(&Client::handshakeHandler, this, std::placeholders::_1));
  });

  if (ec_) {
    throw std::system_error(ec_);
  }
}

template <typename STREAM_TYPE>
void Client::sendRequest(STREAM_TYPE& stream,
                         Request& req,
                         beast_http_response_parser& resp) {
  req.target((req.remotePath()) ? *req.remotePath() : "/");
  req.version(11);

  if (req[beast_http::field::host].empty()) {
    std::string host_header_value = *client_options_.remote_hostname_;
    if (client_options_.ssl_connection_ &&
        (kHTTPSDefaultPort != *client_options_.remote_port_)) {
      host_header_value += ':' + *client_options_.remote_port_;
    } else if (!client_options_.ssl_connection_ &&
               kHTTPDefaultPort != *client_options_.remote_port_) {
      host_header_value += ':' + *client_options_.remote_port_;
    }
    req.set(beast_http::field::host, host_header_value);
  }

  req.prepare_payload();
  req.keep_alive(true);

  if (client_options_.timeout_) {
    timer_.async_wait(
        [=](boost::system::error_code const& ec) { timeoutHandler(ec); });
  }

  beast_http_request_serializer sr{req};

  callNetworkOperation([&]() {
    beast_http::async_write(stream,
                            sr,
                            std::bind(&Client::writeHandler,
                                      this,
                                      std::placeholders::_1,
                                      std::placeholders::_2));
  });

  if (ec_) {
    throw std::system_error(ec_);
  }

  boost::beast::flat_buffer b;

  callNetworkOperation([&]() {
    beast_http::async_read(stream,
                           b,
                           resp,
                           std::bind(&Client::readHandler,
                                     this,
                                     std::placeholders::_1,
                                     std::placeholders::_2));
  });

  if (ec_) {
    throw std::system_error(ec_);
  }

  if (resp.get()["Connection"] == "close") {
    closeSocket();
  }

  if (!client_options_.keep_alive_) {
    closeSocket();
  }
}

bool Client::initHTTPRequest(Request& req) {
  bool create_connection = true;
  if (req.remoteHost()) {
    std::string hostname = *req.remoteHost();
    std::string port;

    if (req.remotePort()) {
      port = *req.remotePort();
    } else if (req.protocol() && (*req.protocol()).compare("https") == 0) {
      port = kHTTPSDefaultPort;
    } else {
      port = kHTTPDefaultPort;
    }

    bool ssl_connection = false;
    if (req.protocol() && (*req.protocol()).compare("https") == 0) {
      ssl_connection = true;
    }

    if (!isSocketOpen() || new_client_options_ ||
        hostname != *client_options_.remote_hostname_ ||
        port != *client_options_.remote_port_ ||
        client_options_.ssl_connection_ != ssl_connection) {
      client_options_.remote_hostname_ = hostname;
      client_options_.remote_port_ = port;
      client_options_.ssl_connection_ = ssl_connection;
      new_client_options_ = false;
      closeSocket();
    } else {
      create_connection = false;
    }
  } else {
    if (!client_options_.remote_hostname_) {
      throw std::runtime_error("Remote hostname missing");
    }

    if (!client_options_.remote_port_) {
      if (client_options_.ssl_connection_) {
        client_options_.remote_port_ = kHTTPSDefaultPort;
      } else {
        client_options_.remote_port_ = kHTTPDefaultPort;
      }
    }
    closeSocket();
  }
  return create_connection;
}

Response Client::sendHTTPRequest(Request& req) {
  if (client_options_.timeout_) {
    timer_.expires_from_now(
        boost::posix_time::seconds(client_options_.timeout_));
  }

  bool retry_connect = false;
  do {
    bool create_connection = true;
    if (!retry_connect) {
      create_connection = initHTTPRequest(req);
    }

    try {
      beast_http_response_parser resp;
      if (create_connection) {
        createConnection();

        if (client_options_.ssl_connection_) {
          encryptConnection();
        }
      }

      if (client_options_.ssl_connection_) {
        sendRequest(*ssl_sock_, req, resp);
      } else {
        sendRequest(sock_, req, resp);
      }

      switch (resp.get().result()) {
      case beast_http::status::moved_permanently:
      case beast_http::status::found:
      case beast_http::status::see_other:
      case beast_http::status::not_modified:
      case beast_http::status::use_proxy:
      case beast_http::status::temporary_redirect:
      case beast_http::status::permanent_redirect: {
        if (!client_options_.follow_redirects_) {
          return Response(resp.release());
        }

        std::string redir_url = Response(resp.release()).headers()["Location"];
        if (!redir_url.size()) {
          throw std::runtime_error(
              "Location header missing in redirect response");
        }

        req.uri(redir_url);
        VLOG(1) << "HTTP(S) request re-directed to: " << redir_url;
        break;
      }
      default:
        return Response(resp.release());
      }
    } catch (std::exception const& /* e */) {
      closeSocket();
      if (!retry_connect && ec_ != boost::asio::error::timed_out) {
        retry_connect = true;
      } else {
        ec_.clear();
        throw;
      }
    }
  } while (true);
}

Response Client::put(Request& req,
                     std::string const& body,
                     std::string const& content_type) {
  req.method(beast_http::verb::put);
  req.body() = body;
  if (!content_type.empty()) {
    req.set(beast_http::field::content_type, content_type);
  }
  return sendHTTPRequest(req);
}

Response Client::post(Request& req,
                      std::string const& body,
                      std::string const& content_type) {
  req.method(beast_http::verb::post);
  req.body() = body;
  if (!content_type.empty()) {
    req.set(beast_http::field::content_type, content_type);
  }
  return sendHTTPRequest(req);
}

Response Client::put(Request& req,
                     std::string&& body,
                     std::string const& content_type) {
  req.method(beast_http::verb::put);
  req.body() = std::move(body);
  if (!content_type.empty()) {
    req.set(beast_http::field::content_type, content_type);
  }
  return sendHTTPRequest(req);
}

Response Client::post(Request& req,
                      std::string&& body,
                      std::string const& content_type) {
  req.method(beast_http::verb::post);
  req.body() = std::move(body);
  if (!content_type.empty()) {
    req.set(beast_http::field::content_type, content_type);
  }
  return sendHTTPRequest(req);
}

Response Client::get(Request& req) {
  req.method(beast_http::verb::get);
  return sendHTTPRequest(req);
}

Response Client::head(Request& req) {
  req.method(beast_http::verb::head);
  return sendHTTPRequest(req);
}

Response Client::delete_(Request& req) {
  req.method(beast_http::verb::delete_);
  return sendHTTPRequest(req);
}
} // namespace http
} // namespace osquery
