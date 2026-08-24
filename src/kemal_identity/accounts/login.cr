module KemalIdentity::Accounts
  # Normalisation of the identifier a person types into a login form.
  #
  # The normalised form is **stored** in `auth_accounts.normalized_login` and looked up by
  # equality. It is deliberately not computed in the `WHERE` clause: doing that stops the
  # index being used, and — worse — lets the uniqueness constraint and the lookup disagree,
  # so two accounts can exist that one query considers the same and another does not
  # (`docs/02-security-model.md`).
  module Login
    # Strips surrounding whitespace and applies Unicode case folding.
    #
    # Case *folding* rather than `downcase`: folding is the operation defined for
    # caseless matching, and it differs from lowercasing in cases that matter — German ß
    # folds to `ss`, so `STRASSE` and `straße` normalise alike, which a plain `downcase`
    # never achieves.
    #
    # ### The limitation, stated rather than hidden
    #
    # This is simple case folding, and v0.1 attempts **no confusable detection**. Two
    # visually identical logins can normalise differently (Latin `a` versus Cyrillic `а`),
    # and two visually distinct ones can normalise alike. An application for which
    # homograph registration is a real threat has to add its own check on the way in; this
    # function is not it.
    def self.normalize(login : String) : String
      login.strip.downcase(Unicode::CaseOptions::Fold)
    end
  end
end
