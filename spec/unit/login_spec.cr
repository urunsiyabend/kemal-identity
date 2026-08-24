require "../spec_helper"

describe KemalIdentity::Accounts::Login do
  describe ".normalize" do
    it "strips surrounding whitespace" do
      KemalIdentity::Accounts::Login.normalize("  ada@example.com  ").should eq("ada@example.com")
    end

    it "folds case" do
      KemalIdentity::Accounts::Login.normalize("Ada@Example.COM").should eq("ada@example.com")
    end

    it "is idempotent, so re-normalising a stored value is harmless" do
      once = KemalIdentity::Accounts::Login.normalize("  Ada@Example.COM ")
      KemalIdentity::Accounts::Login.normalize(once).should eq(once)
    end

    it "leaves an already normal login alone" do
      KemalIdentity::Accounts::Login.normalize("ada@example.com").should eq("ada@example.com")
    end

    it "does not collapse internal whitespace" do
      # Trimming the ends is normalisation; rewriting the middle would silently merge two
      # distinct logins.
      KemalIdentity::Accounts::Login.normalize(" ada smith ").should eq("ada smith")
    end

    # Case folding is not lowercasing. German ß lowercases to itself but folds to "ss", so
    # only folding makes STRASSE and straße match — which is the whole reason for the
    # Unicode::CaseOptions::Fold argument.
    it "folds where downcase would not" do
      KemalIdentity::Accounts::Login.normalize("STRASSE").should eq("strasse")
      KemalIdentity::Accounts::Login.normalize("straße").should eq("strasse")
      KemalIdentity::Accounts::Login.normalize("straße").should eq(
        KemalIdentity::Accounts::Login.normalize("STRASSE")
      )
      # The distinction this spec is really pinning down:
      "straße".downcase.should_not eq("strasse")
    end

    it "folds non-ASCII case" do
      KemalIdentity::Accounts::Login.normalize("ÄDA@example.com").should eq("äda@example.com")
      KemalIdentity::Accounts::Login.normalize("İSTANBUL@example.com").should_not contain("İ")
    end

    it "handles an empty and a whitespace-only login without raising" do
      KemalIdentity::Accounts::Login.normalize("").should eq("")
      KemalIdentity::Accounts::Login.normalize("   ").should eq("")
    end
  end

  # docs/02-security-model.md states this limitation rather than hiding it: v0.1 uses simple
  # case folding and attempts no confusable detection. These specs record the exposure so
  # nobody later assumes it was handled.
  describe "the documented Unicode limitation" do
    it "does not detect homographs: Cyrillic а stays distinct from Latin a" do
      latin = KemalIdentity::Accounts::Login.normalize("ada@example.com")
      cyrillic = KemalIdentity::Accounts::Login.normalize("аda@example.com")
      cyrillic.should_not eq(latin)
    end

    it "does not apply compatibility normalisation" do
      # U+FF41 FULLWIDTH LATIN SMALL LETTER A is a different login from "a".
      KemalIdentity::Accounts::Login.normalize("ａda@example.com").should_not eq("ada@example.com")
    end
  end
end
