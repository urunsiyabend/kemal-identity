require "http/cookie"

module KemalIdentity::Sessions
  # How the session cookie is named and attributed.
  #
  # Validated at construction, which means an incoherent configuration is a startup crash
  # rather than a cookie the browser silently discards in production
  # (`docs/01-architecture.md`).
  struct CookieConfig
    # Default name, and the reason for most of the validation below.
    #
    # ### The `__Host-` consequence, which is not a footnote
    #
    # The prefix forbids a `Domain` attribute, so the cookie is scoped to exactly one host:
    # `app.example.com` and `api.example.com` **cannot share a session**. That is the right
    # default — it stops a compromised sibling subdomain from setting a session cookie for
    # the parent — but it is a wall people hit without understanding why. An application
    # spanning subdomains must set a non-prefixed `name` together with an explicit `domain`,
    # deliberately (`docs/02-security-model.md`).
    DEFAULT_NAME = "__Host-kemal_identity"

    HOST_PREFIX   = "__Host-"
    SECURE_PREFIX = "__Secure-"

    getter name : String
    getter? secure : Bool
    getter? http_only : Bool
    getter samesite : HTTP::Cookie::SameSite
    getter path : String
    getter domain : String?

    def initialize(
      @name : String = DEFAULT_NAME,
      @secure : Bool = true,
      @http_only : Bool = true,
      # `Lax`, not `Strict`: `Strict` breaks return-from-OAuth navigation, where the browser
      # arrives from the provider and would present no cookie. It is defence in depth, never
      # a replacement for a CSRF token.
      @samesite : HTTP::Cookie::SameSite = HTTP::Cookie::SameSite::Lax,
      @path : String = "/",
      @domain : String? = nil,
      # The escape hatch for local development over plain HTTP. Named to be conspicuous in a
      # diff, and defaulting to closed: `secure: false` is otherwise a boot failure, rather
      # than something the shard infers from an environment variable it has no business
      # reading. See `blueprints/0006-session-cookie-and-expiry-boundaries.md`.
      @allow_insecure : Bool = false,
    )
      validate!
    end

    def host_prefixed? : Bool
      @name.starts_with?(HOST_PREFIX)
    end

    # Builds the `Set-Cookie` for a freshly issued token.
    #
    # `max_age` is deliberately optional. Omitting it produces a session cookie that dies
    # with the browser, which is the right default: the server-side row is what decides when
    # a session ends, and a persistent cookie only tells the browser to keep presenting a
    # secret the server has already stopped honouring.
    def build(token : Secret, max_age : Time::Span? = nil) : HTTP::Cookie
      cookie = HTTP::Cookie.new(
        name: @name,
        value: token.reveal,
        path: @path,
        secure: @secure,
        http_only: @http_only,
        samesite: @samesite,
        domain: @domain,
      )
      cookie.max_age = max_age if max_age
      cookie
    end

    # Builds the `Set-Cookie` that clears the session cookie.
    #
    # Same name, same path, same domain — a browser matches on all three, so a cleared cookie
    # that differs in any of them leaves the original in place. The value is emptied and
    # `max_age` is zero.
    def build_cleared : HTTP::Cookie
      cookie = HTTP::Cookie.new(
        name: @name,
        value: "",
        path: @path,
        secure: @secure,
        http_only: @http_only,
        samesite: @samesite,
        domain: @domain,
      )
      cookie.max_age = Time::Span::ZERO
      cookie
    end

    # Reads the raw token out of a request's cookies, or `nil` if it is not there.
    #
    # Takes `HTTP::Cookies` rather than a server context: nothing outside the Kemal layer is
    # allowed to know that `HTTP::Server::Context` exists (`docs/01-architecture.md`).
    def extract(cookies : HTTP::Cookies) : String?
      cookie = cookies[@name]?
      return if cookie.nil?

      value = cookie.value
      value.empty? ? nil : value
    end

    private def validate!
      raise ConfigurationError.new("cookie name must not be empty") if @name.empty?

      unless @secure || @allow_insecure
        raise ConfigurationError.new(
          "session cookie must be Secure. Set allow_insecure: true to permit plain HTTP, " \
          "which is only ever acceptable in local development"
        )
      end

      # SameSite=None is a cross-site cookie, and browsers reject it without Secure. Failing
      # here beats a cookie that silently never arrives.
      if @samesite == HTTP::Cookie::SameSite::None && !@secure
        raise ConfigurationError.new("SameSite=None requires Secure")
      end

      if host_prefixed?
        # These three are exactly what the `__Host-` prefix demands. A browser that sees the
        # prefix violated discards the cookie without a word, so the incoherent middle ground
        # has to be refused here.
        unless @secure
          raise ConfigurationError.new("a #{HOST_PREFIX} cookie must be Secure")
        end

        unless @path == "/"
          raise ConfigurationError.new(
            "a #{HOST_PREFIX} cookie requires path \"/\", got #{@path.inspect}"
          )
        end

        unless @domain.nil?
          raise ConfigurationError.new(
            "a #{HOST_PREFIX} cookie must not set a domain, got #{@domain.inspect}. " \
            "To share a session across subdomains, choose a name without the " \
            "#{HOST_PREFIX} prefix and set the domain deliberately — and understand that " \
            "any subdomain can then set a session cookie for the parent"
          )
        end
      elsif @name.starts_with?(SECURE_PREFIX) && !@secure
        raise ConfigurationError.new("a #{SECURE_PREFIX} cookie must be Secure")
      end
    end
  end
end
