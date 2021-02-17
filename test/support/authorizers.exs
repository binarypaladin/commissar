defmodule Commissar.Test.EmptyAuthorizer do
  use Commissar.Authorization

  @impl true
  def policies, do: []
end

defmodule Commissar.Test.UserAuthorizer do
  use Commissar.Authorization

  @impl true
  def policies, do: [:is_active_user, :is_super_user]

  @impl true
  def policy(:is_active_user, %{disabled: true}, _, _), do: {:error, :user_disabled}

  def policy(:is_active_user, %{disabled: false}, _, _), do: :continue

  def policy(:is_active_user, _, _, _), do: {:error, :user_not_present}

  def policy(:is_super_user, %{super_user: true}, _, _), do: :ok
end

defmodule Commissar.Test.PermissionAuthorizer do
  use Commissar.Authorization

  @impl true
  def policies, do: [:has_permission]

  @impl true
  def policy(:has_permission, _, action, {_, permissions}) do
    cond do
      Enum.member?(permissions, "full_control") -> :ok
      Enum.member?(permissions, action) -> :ok
      true -> :continue
    end
  end
end

defmodule Commissar.Test.OwnerAuthorizer do
  use Commissar.Authorization

  @impl true
  def policies do
    [
      Commissar.Test.UserAuthorizer.export_policies(),
      :is_owner,
      Commissar.Test.PermissionAuthorizer.export_policies()
    ]
  end

  @impl true
  def policy(:is_owner, %{id: id}, _, {%{owner_id: owner_id}, _})
      when id == owner_id,
      do: :ok
end

defmodule Commissar.Test.ComplexAuthorizer do
  use Commissar.Authorization

  @impl true
  def policies do
    [
      Commissar.Test.UserAuthorizer.export_policy(:is_active_user),
      :cannot_be_destroyed,
      Commissar.Test.UserAuthorizer.export_policy(:is_super_user),
      :has_public_read_access,
      fn
        _, "update", {%{public_write: true}, _} -> :ok
        _, _, _ -> :continue
      end,
      Commissar.Test.PermissionAuthorizer.export_policies()
    ]
  end

  @impl true
  def policy(:cannot_be_destroyed, _, "destroy", {%{locked: true}, _}),
    do: {:error, :resource_locked}

  def policy(:has_public_read_access, _, "read", {%{public_read: true}, _}), do: :ok
end
