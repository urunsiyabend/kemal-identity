module KemalIdentity::Kemal
  # Adopts a login from the session system this application is migrating **off**.
  #
  # `docs/06-roadmap.md`'s migration step 3: "A `LegacySessionAuthenticator` reads the old
  # `kemal-session` cookie, extracts **only the subject**, mints a new auth session and issues
  # the new cookie. Secrets are never copied from one system to the other. After a grace period
  # the legacy authenticator is removed and any remaining old sessions become invalid."
  #
  # Nobody is signed out by the deployment that introduces this shard, and nobody has to log in
  # twice. It is meant to be deleted.
  #
  # ```
  # # Built first and then passed to `use`. Kemal's `use` is a macro, so a block written after
  # # `use Handler.new(...)` attaches to `use` and the constructor complains it got none.
  # LEGACY = KemalIdentity::Kemal::LegacySessionHandler.new(clear_cookie: "kemal_sessid") do |env|
  #   Kemal::Session.get(env).try(&.string?("user_id"))
  # end
  #
  # use KemalIdentity::Kemal::AuthenticationHandler.new
  # use LEGACY
  # ```
  #
  # ### The block returns a subject and nothing else
  #
  # Not a principal, not an assurance level, not a timestamp, and above all not a token. The
  # block's whole job is to answer "who was this old cookie for", and everything after that is
  # this shard's. That is what "secrets are never copied" means concretely: whatever signed or
  # keyed the old session stays in the old system and dies with it.
  #
  # Reading the old cookie is the application's job because only the application knows what
  # wrote it — kemal-session with a memory store, a signed cookie from a Sinatra-shaped app, a
  # row in a table somebody else's framework owns. A shard that guessed would be guessing about
  # the one thing it must not get wrong.
  #
  # ### An adopted session is `Remembered`, not `Password`
  #
  # The old cookie proves that somebody authenticated at some point, to a system this one
  # cannot inspect. It does not prove that the account holder is present, and it does not say
  # when they last typed anything. `AssuranceLevel::Remembered` is exactly that situation, and
  # it has the right consequences already: `Principal#fresh?` is false, so `require_fresh!`
  # forces a real re-authentication before anything sensitive, and `require_assurance!` refuses
  # it outright.
  #
  # Claiming `Password` instead would let an adopted session change an email address on the
  # strength of a cookie from a system that is being retired for a reason.
  #
  # ### Where it goes, and why it is a separate handler
  #
  # Immediately after `AuthenticationHandler`, which has by then tried the session cookie, a
  # bearer token and remember-me. This runs only when all of those found nothing, so a live
  # session is never replaced by an adopted one, and the legacy path is the last thing tried
  # rather than the first.
  #
  # Separate from `AuthenticationHandler` because it is temporary. Deleting a `use` line is a
  # smaller decision than editing a configuration that also does five permanent things, and the
  # day it is deleted is the day the old sessions stop working — which is the point.
  class LegacySessionHandler < ::Kemal::Handler
    # `clear_cookie` is the old cookie's name, cleared once the login has been adopted so the
    # browser stops presenting a credential to a system that no longer reads it. Nil leaves it
    # alone, for an old session that lives somewhere other than a cookie.
    def initialize(
      @clear_cookie : String? = nil,
      @cookie_path : String = "/",
      @app : Application? = nil,
      &@subject : HTTP::Server::Context -> String?
    )
    end

    def call(env : HTTP::Server::Context)
      # `env.auth` raises when `AuthenticationHandler` is not installed, which is the right
      # answer: this handler alone would silently do nothing.
      adopt(env) if env.auth.anonymous?

      call_next(env)
    end

    private def adopt(env : HTTP::Server::Context) : Nil
      subject = @subject.call(env)
      return if subject.nil? || subject.empty?

      principal = env.auth.adopt_legacy_session!(subject)

      if principal.nil?
        # The old system named an account this one does not have, or one that is disabled.
        # Clearing regardless: the cookie is not going to start working.
        clear_legacy_cookie(env)
        Log.info &.emit("session.legacy_refused", subject: subject)
        return
      end

      clear_legacy_cookie(env)

      Log.info &.emit("session.legacy_adopted", subject: principal.subject)
    end

    private def clear_legacy_cookie(env : HTTP::Server::Context) : Nil
      name = @clear_cookie
      return if name.nil?

      # Same name and path as whatever set it, because a browser matches on both and a clearing
      # cookie that differs in either leaves the original in place.
      env.response.cookies << HTTP::Cookie.new(
        name: name, value: "", path: @cookie_path, expires: Time.unix(0), http_only: true
      )
    end
  end
end
