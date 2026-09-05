module KemalIdentity
  # A way of proving an identity, when a policy needs to name one.
  #
  # Deliberately **not** a general vocabulary of everything this shard can authenticate with.
  # It names the methods a guard can ask about by name, which today is one: a password is the
  # only proof whose *own* recency the shard records
  # (`blueprints/0031-the-password-is-its-own-evidence.md`). Strength questions are
  # `AssuranceLevel` and recency questions are `Principal#fresh?`; this exists for the third
  # kind — "it has to have been *this*" — which only the password currently answers.
  #
  # A member is added when the evidence behind it is, and not before: an enum member with no
  # timestamp to compare against would compile into a guard that can never be satisfied, which
  # is the trap `require_recent_password!` avoids by only ever naming what exists.
  #
  # Not persisted, and not a wire format. `AssuranceLevel`'s numbering rules do not apply here,
  # and this is not RFC 8176's `amr` — that registry has 22 values and none of them means
  # "recovery code" (`blueprints/0030`), so it is not a vocabulary this shard can adopt.
  enum AuthenticationMethod
    # A password was typed. `Principal#password_verified_at` is the evidence.
    Password
  end
end
