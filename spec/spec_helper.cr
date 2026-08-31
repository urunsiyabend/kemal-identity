# The suite's entry point. Everything it used to define now lives under
# `src/kemal_identity/testing`, published as `require "kemal_identity/testing"` so that an
# adapter author gets the same doubles and the same contracts this suite runs --
# `blueprints/0025-maturity-validation-results.md`, DEV-02.
require "../src/kemal_identity/testing"
require "../src/kemal_identity/testing/contracts"
