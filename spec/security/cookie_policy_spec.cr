require "../spec_helper"

# The cookie blockers from docs/05-testing.md. Attributes are asserted by parsing the
# rendered Set-Cookie header, never by reading the config object back — the config saying
# `secure` and the header carrying `Secure` are two different claims, and only the second one
# reaches a browser.
private def set_cookie_header(config : KemalIdentity::Sessions::CookieConfig, token : String) : String
  config.build(KemalIdentity::Secret.new(token)).to_set_cookie_header
end

describe "session cookie attributes" do
  it "sets Secure, HttpOnly, SameSite and Path by default" do
    header = set_cookie_header(KemalIdentity::Sessions::CookieConfig.new, "a" * 43)

    header.should contain("Secure")
    header.should contain("HttpOnly")
    header.should contain("SameSite=Lax")
    header.should contain("path=/")
  end

  it "uses the __Host- prefixed name by default" do
    KemalIdentity::Sessions::CookieConfig.new.name.should start_with("__Host-")
  end

  it "sets no domain by default, which is what scopes the cookie to one host" do
    set_cookie_header(KemalIdentity::Sessions::CookieConfig.new, "a" * 43).should_not contain("domain")
  end

  it "carries the token as the cookie value" do
    set_cookie_header(KemalIdentity::Sessions::CookieConfig.new, "abc123").should contain("abc123")
  end

  # A browser matches a clearing cookie on name, path and domain. Differ in any one and the
  # original survives, so logout would leave the cookie in place.
  it "clears with the same name, path and domain" do
    config = KemalIdentity::Sessions::CookieConfig.new(
      name: "kemal_identity", domain: "example.com", path: "/app"
    )
    cleared = config.build_cleared.to_set_cookie_header

    cleared.should contain("kemal_identity=;")
    cleared.should contain("domain=example.com")
    cleared.should contain("path=/app")
    cleared.should contain("max-age=0")
  end

  it "omits max-age by default, so the cookie dies with the browser" do
    set_cookie_header(KemalIdentity::Sessions::CookieConfig.new, "a" * 43).should_not contain("max-age")
  end
end

# docs/02-security-model.md: the incoherent middle ground must be refused at boot, not left
# to a browser to discard silently in production.
describe "boot-time cookie validation" do
  it "refuses a __Host- name with a domain" do
    error = expect_raises(KemalIdentity::ConfigurationError) do
      KemalIdentity::Sessions::CookieConfig.new(domain: "example.com")
    end
    error.message.to_s.should contain("must not set a domain")
  end

  it "refuses a __Host- name with a non-root path" do
    expect_raises(KemalIdentity::ConfigurationError) do
      KemalIdentity::Sessions::CookieConfig.new(path: "/app")
    end
  end

  it "refuses a __Host- name without Secure" do
    expect_raises(KemalIdentity::ConfigurationError) do
      KemalIdentity::Sessions::CookieConfig.new(secure: false, allow_insecure: true)
    end
  end

  it "refuses a __Secure- name without Secure" do
    expect_raises(KemalIdentity::ConfigurationError) do
      KemalIdentity::Sessions::CookieConfig.new(
        name: "__Secure-kemal_identity", secure: false, allow_insecure: true
      )
    end
  end

  it "refuses an insecure cookie unless it is opted into explicitly" do
    expect_raises(KemalIdentity::ConfigurationError) do
      KemalIdentity::Sessions::CookieConfig.new(name: "kemal_identity", secure: false)
    end
  end

  it "allows an insecure cookie only with the conspicuous opt-in, for local development" do
    config = KemalIdentity::Sessions::CookieConfig.new(
      name: "kemal_identity", secure: false, allow_insecure: true
    )
    config.build(KemalIdentity::Secret.new("a" * 43)).to_set_cookie_header.should_not contain("Secure")
  end

  it "refuses SameSite=None without Secure" do
    expect_raises(KemalIdentity::ConfigurationError) do
      KemalIdentity::Sessions::CookieConfig.new(
        name: "kemal_identity",
        secure: false,
        allow_insecure: true,
        samesite: HTTP::Cookie::SameSite::None,
      )
    end
  end

  it "accepts the documented way out for an application spanning subdomains" do
    config = KemalIdentity::Sessions::CookieConfig.new(name: "kemal_identity", domain: "example.com")
    config.build(KemalIdentity::Secret.new("a" * 43))
      .to_set_cookie_header.should contain("domain=example.com")
  end

  it "refuses an empty name" do
    expect_raises(KemalIdentity::ConfigurationError) { KemalIdentity::Sessions::CookieConfig.new(name: "") }
  end
end

describe "reading the cookie back" do
  it "extracts the token" do
    cookies = HTTP::Cookies.new
    cookies << HTTP::Cookie.new(name: "__Host-kemal_identity", value: "token-value")

    KemalIdentity::Sessions::CookieConfig.new.extract(cookies).should eq("token-value")
  end

  it "returns nil when the cookie is absent" do
    KemalIdentity::Sessions::CookieConfig.new.extract(HTTP::Cookies.new).should be_nil
  end

  it "treats an empty value as absent" do
    cookies = HTTP::Cookies.new
    cookies << HTTP::Cookie.new(name: "__Host-kemal_identity", value: "")

    KemalIdentity::Sessions::CookieConfig.new.extract(cookies).should be_nil
  end

  it "ignores a cookie of another name" do
    cookies = HTTP::Cookies.new
    cookies << HTTP::Cookie.new(name: "session", value: "token-value")

    KemalIdentity::Sessions::CookieConfig.new.extract(cookies).should be_nil
  end
end
