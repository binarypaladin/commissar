defmodule Commissar.AuthorizerTest do
  use ExUnit.Case

  alias Commissar.Test.{ComplexAuthorizer, EmptyAuthorizer}

  test "catch all rule" do
    assert EmptyAuthorizer.check(nil, nil, nil) == {:deny, :no_matching_rules}
  end

  test "def-based, exported, and anonymous function based rules" do
    user = %{disabled: false, super_user: false}

    resource = %{locked: false, public_read: false, public_write: false}

    context = {resource, ["read"]}

    disabled_user = %{user | disabled: true, super_user: true}
    refute ComplexAuthorizer.allow?(disabled_user, "update", context)
    assert ComplexAuthorizer.check(disabled_user, "update", context) == {:deny, :user_disabled}

    super_user = %{user | super_user: true}

    assert ComplexAuthorizer.check(super_user, "destroy", {%{resource | locked: true}, []}) ==
             {:deny, :resource_locked}

    assert ComplexAuthorizer.allow?(super_user, "update", context)
    assert ComplexAuthorizer.check(super_user, "update", context) == :allow

    public_read_context = {%{resource | public_read: true}, []}
    assert ComplexAuthorizer.check(user, "read", public_read_context) == :allow

    assert ComplexAuthorizer.check(user, "update", public_read_context) ==
             {:deny, :no_matching_rules}

    public_write_context = {%{resource | public_write: true}, []}

    assert ComplexAuthorizer.check(user, "update", public_write_context) ==
             :allow

    assert ComplexAuthorizer.check(user, "delete", public_write_context) ==
             {:deny, :no_matching_rules}

    assert ComplexAuthorizer.check(user, "read", context) == :allow
    assert ComplexAuthorizer.check(user, "update", {resource, ["update"]}) == :allow
    assert ComplexAuthorizer.check(user, "destroy", context) == {:deny, :no_matching_rules}
  end
end
