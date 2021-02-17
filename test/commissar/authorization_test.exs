defmodule Commissar.AuthorizationTest do
  use ExUnit.Case

  alias Commissar.Test.{ComplexAuthorizer, EmptyAuthorizer}

  test "catch all policy" do
    assert EmptyAuthorizer.authorize(nil, nil, nil) ==
             {:error, :no_matching_policy}
  end

  test "def-based, exported, and anonymous function based policies" do
    user = %{disabled: false, super_user: false}

    resource = %{locked: false, public_read: false, public_write: false}

    context = {resource, ["read"]}

    disabled_user = %{user | disabled: true, super_user: true}
    refute ComplexAuthorizer.allow?(disabled_user, "update", context)

    assert ComplexAuthorizer.authorize(disabled_user, "update", context) ==
             {:error, :user_disabled}

    super_user = %{user | super_user: true}

    assert ComplexAuthorizer.authorize(super_user, "destroy", {%{resource | locked: true}, []}) ==
             {:error, :resource_locked}

    assert ComplexAuthorizer.allow?(super_user, "update", context)
    assert ComplexAuthorizer.authorize(super_user, "update", context) == :ok

    public_read_context = {%{resource | public_read: true}, []}
    assert ComplexAuthorizer.authorize(user, "read", public_read_context) == :ok

    assert ComplexAuthorizer.authorize(user, "update", public_read_context) ==
             {:error, :no_matching_policy}

    public_write_context = {%{resource | public_write: true}, []}

    assert ComplexAuthorizer.authorize(user, "update", public_write_context) ==
             :ok

    assert ComplexAuthorizer.authorize(user, "delete", public_write_context) ==
             {:error, :no_matching_policy}

    assert ComplexAuthorizer.authorize(user, "read", context) == :ok
    assert ComplexAuthorizer.authorize(user, "update", {resource, ["update"]}) == :ok

    assert ComplexAuthorizer.authorize(user, "destroy", context) ==
             {:error, :no_matching_policy}
  end
end
