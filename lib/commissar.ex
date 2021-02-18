defmodule Commissar do
  @moduledoc """
  Commissar provides relatively simple pattern for creating sets of policies to
  see if a subject is allowed to execute a particular action related to a given
  context.

  A subject is whatever is trying to execute a particular action. In most cases
  this will probably be a user, but it could just as easily be a group or any
  other resource in an application.

  A context is any term that provides the authorization policies with what will
  be required to decide if the subject is allowed to execute a particular
  action. This might be another system resource, but it may also be a tuple
  containing some kind of permissions related to the user along with a given
  resource. They could be in a map as well. It doesn't matter so long as they
  conform to the expectations of the policies.

  An action is a descriptor of what subject wants to execute on the context. In
  most cases it will be an atom or a string with some sort of CRUD type name
  such as `read` or `update`.

  A policy is a function that takes an action, a subject, and a context and
  returns one of six responses (see `policy_result` type).
  """

  @typedoc """
  One of six possible responses:

  * `:ok` - The subject is allowed. Do not process any further policies.
  * `:continue` - The policy could neither allow nor deny the subject. Move on
    to the next policy. If no policies remain, the default response is to deny.
  * `:error` - The subject is denied. Do not process any further policies.
  * `{:error, reason}` - A denial with more information. The `reason` could be
    anything from an atom with some kind of error code to a map with a bunch of
    contextual information.
  * `false`: Identical to `:error`.
  * `true`: Identical to `:ok`.

  `true` and `false` are conveniences boolean checks which are common in
  authorization routines.
  """
  @type policy_result() :: :ok | :continue | :error | {:error | any()} | false | true

  @typedoc """
  A function that takes an action, a subject, and a context, and returns a
  `policy_result`.
  """
  @type policy() :: (any(), any(), any() -> policy_result())

  @doc """
  Returns a boolean for a given authorize result. In general, this function
  won't be called directly.
  """
  @spec allow?(any()) :: boolean()
  def allow?(:ok), do: true

  def allow?(_), do: false

  @doc """
  Similar to `authorize/4` but returns a boolean response instead. This should
  be used when you have no use for any potential denial reasons.
  """
  @spec allow?(any(), any(), any(), [policy()]) :: boolean()
  def allow?(subject, action, context, policies) do
    allow?(authorize(subject, action, context, policies))
  end

  @doc """
  Checks to see whether a subject attempting an action is allowed to do so on a
  context with a given set of policies.

  Note that the response is not a `policy_result`.
  """
  @spec authorize(any(), any(), any(), [policy()]) :: :ok | {:error | any()}
  def authorize(subject, action, context, policies) when is_list(policies) do
    check_policies(:continue, subject, action, context, policies)
  end

  @doc """
  Exports a single policy from an authorizer to used as a policy.
  """
  @spec export_policy(module(), atom()) :: policy()
  def export_policy(authorizer_module, policy_name)
      when is_atom(authorizer_module) and is_atom(policy_name),
      do: &apply(authorizer_module, :policy, [policy_name, &1, &2, &3])

  @doc """
  Exports all policies from an authorizer module.
  """
  @spec export_policies(module()) :: [policy()]
  def export_policies(authorizer_module) when is_atom(authorizer_module) do
    authorizer_module.policies()
    |> List.flatten()
    |> Enum.map(&get_policy(authorizer_module, &1))
  end

  defp check_policies(:continue, _subject, _action, _context, []) do
    {:error, :no_matching_policy}
  end

  defp check_policies(:continue, subject, action, context, [policy | rest]) do
    policy.(subject, action, context)
    |> check_policies(subject, action, context, rest)
  end

  defp check_policies({:error, _} = result, _subject, _action, _context, _policies), do: result

  defp check_policies(result, _subject, _action, _context, _policies)
       when result in [true, :ok],
       do: :ok

  defp check_policies(result, _subject, _action, _context, _policies)
       when result in [false, :error],
       do: {:error, :access_denied}

  defp get_policy(_, func) when is_function(func, 3), do: func

  defp get_policy(authorizer_module, policy_name),
    do: export_policy(authorizer_module, policy_name)
end
