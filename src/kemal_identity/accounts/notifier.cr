module KemalIdentity::Accounts
  # Somebody asked to reset the password on this account.
  #
  # ### This struct carries a raw token, and it is the only place one leaves the shard
  #
  # `token` is the secret the link must contain — the application cannot build a URL from a
  # digest, so there is no version of this that does not hand it over. Everything downstream of
  # here is the application's responsibility, and `docs/02-security-model.md`'s token rules
  # still apply to it: never log it, never store it, and prefer a form post over a query string
  # so it does not reach a `Referer` header.
  #
  # It is a `Secret`, so an accidental interpolation into a log line prints `[REDACTED]` rather
  # than a working password reset.
  struct PasswordResetRequested
    getter account_id : String

    # The normalised login the message goes to. The application needs an address to send to,
    # and this is the one the account was found by.
    getter login : String

    getter token : Secret
    getter expires_at : Time

    def initialize(@account_id : String, @login : String, @token : Secret, @expires_at : Time)
    end
  end

  # An address needs proving. Same rules as above for `token`.
  struct EmailConfirmationRequested
    getter account_id : String
    getter login : String
    getter token : Secret
    getter expires_at : Time

    def initialize(@account_id : String, @login : String, @token : Secret, @expires_at : Time)
    end
  end

  # The password on this account changed. Carries no token, because there is nothing to click.
  #
  # Worth sending even though nobody asked for it: it is how somebody finds out that an
  # attacker who reached their mailbox has taken the account, and it is the only notification
  # here whose value is entirely in being unsolicited.
  struct PasswordChanged
    getter account_id : String
    getter login : String
    getter at : Time

    def initialize(@account_id : String, @login : String, @at : Time)
    end
  end

  # Anything the application may need to tell an account holder about.
  #
  # A union rather than a base class with subclasses, for the same reason `Outcome` is one: a
  # `case ... in` over it is exhaustive, so adding a notification in v0.3 becomes a compile
  # error in every `Notifier` rather than a message that silently never sends.
  alias Notification = PasswordResetRequested | EmailConfirmationRequested | PasswordChanged

  # Delivery. The shard decides *what* to say and the application decides *how* to say it.
  #
  # There is no SMTP here, no templates, and no default implementation that quietly does
  # nothing — `docs/00-scope.md` puts all three out of scope, and a null default would turn a
  # forgotten configuration into password reset emails that are never sent, discovered by a
  # user who cannot get into their account.
  #
  # ### `deliver` must return promptly
  #
  # This is a contract, not a suggestion, and it is load-bearing for a security property.
  #
  # `Service#request_password_reset` must take the same time whether or not the address
  # exists, or it becomes an account oracle — somebody enumerates a customer list by timing the
  # forgot-password form. The service equalises everything it controls, but if `deliver` opens
  # an SMTP connection and waits, the existing-account path is a network round trip longer than
  # the other, and the oracle is back.
  #
  # So: enqueue and return. Write a row, push to a job queue, hand it to a background fiber —
  # anything that does not block on somebody else's server.
  abstract class Notifier
    abstract def deliver(notification : Notification) : Nil
  end
end
