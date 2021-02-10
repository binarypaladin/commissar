defmodule Commissar.Test.EmptyAuthorizer do
  use Commissar.Authorizer

  @impl true
  def rules, do: []
end

defmodule Commissar.Test.UserAuthorizer do
  use Commissar.Authorizer

  @impl true
  def rules, do: [:is_active_user, :is_super_user]

  @impl true
  def rule(:is_active_user, %{disabled: true}, _, _), do: {:deny, :user_disabled}

  def rule(:is_active_user, %{disabled: false}, _, _), do: :continue

  def rule(:is_active_user, _, _, _), do: {:deny, :user_not_present}

  def rule(:is_super_user, %{super_user: true}, _, _), do: :allow
end

defmodule Commissar.Test.PermissionAuthorizer do
  use Commissar.Authorizer

  @impl true
  def rules, do: [:has_permission]

  @impl true
  def rule(:has_permission, _, action, {_, permissions}) do
    cond do
      Enum.member?(permissions, "full_control") -> :allow
      Enum.member?(permissions, action) -> :allow
      true -> :continue
    end
  end
end

defmodule Commissar.Test.OwnerAuthorizer do
  use Commissar.Authorizer

  @impl true
  def rules do
    [
      Commissar.Test.UserAuthorizer.export_rules(),
      :is_owner,
      Commissar.Test.PermissionAuthorizer.export_rules()
    ]
  end

  @impl true
  def rule(:is_owner, %{id: id}, _, {%{owner_id: owner_id}, _})
      when id == owner_id,
      do: :allow
end

defmodule Commissar.Test.ComplexAuthorizer do
  use Commissar.Authorizer

  @impl true
  def rules do
    [
      Commissar.Test.UserAuthorizer.export_rule(:is_active_user),
      :cannot_be_destroyed,
      Commissar.Test.UserAuthorizer.export_rule(:is_super_user),
      :has_public_read_access,
      fn
        _, "update", {%{public_write: true}, _} -> :allow
        _, _, _ -> :continue
      end,
      Commissar.Test.PermissionAuthorizer.export_rules()
    ]
  end

  @impl true
  def rule(:cannot_be_destroyed, _, "destroy", {%{locked: true}, _}),
    do: {:deny, :resource_locked}

  def rule(:has_public_read_access, _, "read", {%{public_read: true}, _}), do: :allow
end
