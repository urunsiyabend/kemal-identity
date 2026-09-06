require "../spec_helper"
require "../../src/kemal_identity/kemal"

# `blueprints/0034`: the wrong handler order compiles, starts, and fails later as a 500 where a
# 401 belonged or a guard reading a principal nobody resolved.
#
# Every example passes its own chain rather than touching `Kemal::Config::CUSTOM_HANDLERS`. The
# whole suite is one binary and `spec/integration/kemal_spec.cr` has a real application in that
# global, so a spec that mutated it would be reordering the handlers another file is testing.
private def chain(*handlers : HTTP::Handler) : Array(Tuple(Int32?, HTTP::Handler))
  handlers.to_a.map { |handler| {nil.as(Int32?), handler.as(HTTP::Handler)} }
end

private def error_handler : HTTP::Handler
  KemalIdentity::Kemal::ErrorHandler.new(login_path: "/login")
end

private def authentication_handler : HTTP::Handler
  KemalIdentity::Kemal::AuthenticationHandler.new
end

private def csrf_handler : HTTP::Handler
  KemalIdentity::Kemal::CSRFHandler.new
end

private def path_guard(prefix : String) : HTTP::Handler
  KemalIdentity::Kemal::PathGuard.new(prefix: prefix)
end

private def legacy_handler : HTTP::Handler
  KemalIdentity::Kemal::LegacySessionHandler.new { |_| nil }
end

describe "validating the handler chain" do
  it "accepts the documented order" do
    KemalIdentity::Kemal.validate_middleware_order!(
      chain(error_handler, authentication_handler, csrf_handler, path_guard("/admin"))
    )
  end

  it "accepts a chain with the optional handlers left out" do
    KemalIdentity::Kemal.validate_middleware_order!(chain(error_handler, authentication_handler))
  end

  # An application that installs none of this has not misconfigured it.
  it "says nothing about a chain with no KemalIdentity handlers in it" do
    KemalIdentity::Kemal.validate_middleware_order!(
      [] of Tuple(Int32?, HTTP::Handler)
    )
  end

  it "accepts more than one PathGuard, which is the documented shape" do
    KemalIdentity::Kemal.validate_middleware_order!(
      chain(error_handler, authentication_handler, path_guard("/admin"), path_guard("/account"))
    )
  end

  # The error handler inside the thing that raises never sees the exception, so `require!`
  # renders a 500 instead of a 401.
  it "refuses an error handler registered after authentication" do
    expect_raises(KemalIdentity::ConfigurationError, /ErrorHandler is registered after/) do
      KemalIdentity::Kemal.validate_middleware_order!(
        chain(authentication_handler, error_handler)
      )
    end
  end

  it "refuses a CSRF handler that runs before the principal exists" do
    expect_raises(KemalIdentity::ConfigurationError, /AuthenticationHandler is registered after \S+CSRFHandler/) do
      KemalIdentity::Kemal.validate_middleware_order!(
        chain(error_handler, csrf_handler, authentication_handler)
      )
    end
  end

  it "refuses a guard that runs before the principal exists" do
    expect_raises(KemalIdentity::ConfigurationError, /AuthenticationHandler is registered after \S+PathGuard/) do
      KemalIdentity::Kemal.validate_middleware_order!(
        chain(error_handler, path_guard("/admin"), authentication_handler)
      )
    end
  end

  # The legacy adapter goes *after* authentication, so an old cookie is adopted only once the
  # session cookie, the bearer token and remember-me have all found nothing. Before it, an
  # adopted session would replace a live one.
  it "accepts the legacy adapter in its documented place" do
    KemalIdentity::Kemal.validate_middleware_order!(
      chain(error_handler, authentication_handler, legacy_handler, csrf_handler)
    )
  end

  it "refuses a legacy adapter that runs before authentication" do
    expect_raises(KemalIdentity::ConfigurationError, /adopted session replaces a real one/) do
      KemalIdentity::Kemal.validate_middleware_order!(
        chain(error_handler, legacy_handler, authentication_handler)
      )
    end
  end

  it "refuses a legacy adapter registered after the CSRF handler" do
    expect_raises(KemalIdentity::ConfigurationError, /act on the session this may have adopted/) do
      KemalIdentity::Kemal.validate_middleware_order!(
        chain(error_handler, authentication_handler, csrf_handler, legacy_handler)
      )
    end
  end

  it "refuses a chain whose guards have no error handler to answer through" do
    expect_raises(KemalIdentity::ConfigurationError, /ErrorHandler is not registered/) do
      KemalIdentity::Kemal.validate_middleware_order!(chain(authentication_handler, csrf_handler))
    end
  end

  it "refuses a chain with nothing to populate env.auth" do
    expect_raises(KemalIdentity::ConfigurationError, /AuthenticationHandler is not registered/) do
      KemalIdentity::Kemal.validate_middleware_order!(chain(error_handler, csrf_handler))
    end
  end

  it "refuses a handler registered twice" do
    expect_raises(KemalIdentity::ConfigurationError, /AuthenticationHandler is registered 2 times/) do
      KemalIdentity::Kemal.validate_middleware_order!(
        chain(error_handler, authentication_handler, authentication_handler)
      )
    end
  end

  # `use handler, 0` puts it ahead of Kemal::InitHandler, which since Kemal 1.13.0 owns
  # temporary-file cleanup — and any explicit position makes registration order stop being the
  # order this check is reading.
  it "refuses an explicit position" do
    expect_raises(KemalIdentity::ConfigurationError, /explicit position \(0\)/) do
      KemalIdentity::Kemal.validate_middleware_order!(
        [{0.as(Int32?), authentication_handler.as(HTTP::Handler)},
         {nil.as(Int32?), error_handler.as(HTTP::Handler)}]
      )
    end
  end

  # One round trip to fix a chain with two things wrong, which is what Django's system checks
  # do rather than reporting the first and stopping.
  it "names every problem it found" do
    message = expect_raises(KemalIdentity::ConfigurationError) do
      KemalIdentity::Kemal.validate_middleware_order!(chain(csrf_handler, path_guard("/admin")))
    end.message.or_fail

    message.should contain("AuthenticationHandler is not registered")
    message.should contain("ErrorHandler is not registered")
  end
end
