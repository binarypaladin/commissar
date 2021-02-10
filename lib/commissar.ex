defmodule Commissar do
  @moduledoc """
  Commissar provides relatively simple pattern for creating sets of rules to see
  if a subject is allowed to execute a particular action related to a given
  context.

  A subject is whatever is trying to execute a particular action. In most cases
  this will probably be a user, but it could just as easily be a group or any
  other resource in an application.

  A context is any term that provides the authorization rules with what will be
  required to decide if the subject is allowed to execute a particular action.
  This might be another system resource, but it may also be a tuple containing
  some kind of permissions related to the user along with a given resource.
  They could be in a map as well. It doesn't matter so long as they conform to
  the expectations of the rules.

  An action is a descriptor of what subject wants to exectute on the context. In
  most cases it will be an atom or a string with some sort of CRUD type name
  such as `read` or `update`.

  A rule is a function that takes an action, a subject, and a context and
  returns one of four responses (see `rule_result` type).
  """

  @typedoc """
  One of four possible responses:

  * `:allow` - The subject is allowed. Do not process any further rules.
  * `:continue` - The rule could neither allow nor deny the subject. Move on to
    the next rule. If no rules remain, the default response is to deny.
  * `:deny` - The subject is denied. Do not process any further rules.
  * `{:deny, reason}` - A denial with more information. The `reason` could be
    anything from an atom with some kind of error code to a map with a bunch of
    contextual information.
  """
  @type rule_result() :: :allow | :continue | :deny | {:deny | any()}

  @typedoc """
  A function that takes an action, a subject, and a context, and returns a
  `rule_result`.
  """
  @type rule() :: (any(), any(), any() -> rule_result())

  @doc """
  Returns a boolean for a given check result. In general, this function won't
  be called directly.
  """
  @spec allow?(any()) :: boolean()
  def allow?(:allow), do: true

  def allow?(_), do: false

  @doc """
  Similar to `check/4` but returns a boolean response instead. This should be
  used when you have no use for any potential denial reasons.
  """
  @spec allow?(any(), any(), any(), [rule()]) :: boolean()
  def allow?(subject, action, context, rules) do
    allow?(check(subject, action, context, rules))
  end

  @doc """
  Checks to see whether a subject attempting an action is allowed to do so on a
  context with a given set of rules.

  Note that the response is not a `rule_result`.
  """
  @spec check(any(), any(), any(), [rule()]) :: :allow | {:deny | any()}
  def check(subject, action, context, rules) when is_list(rules) do
    check_rules(:continue, subject, action, context, rules)
  end

  @doc """
  Exports a single rule from an authorizer to used as a rule.
  """
  @spec export_rule(module(), atom()) :: rule()
  def export_rule(authorizer_module, rule_name)
      when is_atom(authorizer_module) and is_atom(rule_name),
      do: &apply(authorizer_module, :rule, [rule_name, &1, &2, &3])

  @doc """
  Exports all rules from an authorizer module.
  """
  @spec export_rules(module()) :: [rule()]
  def export_rules(authorizer_module) when is_atom(authorizer_module) do
    authorizer_module.rules()
    |> List.flatten()
    |> Enum.map(&get_rule(authorizer_module, &1))
  end

  defp check_rules(:allow, _subject, _action, _context, _rules), do: :allow

  defp check_rules(:continue, _subject, _action, _context, []), do: {:deny, :no_matching_rules}

  defp check_rules(:continue, subject, action, context, [rule | rest]) do
    rule.(subject, action, context)
    |> check_rules(subject, action, context, rest)
  end

  defp check_rules(:deny, _subject, _action, _context, _rules), do: {:deny, :access_denied}

  defp check_rules({:deny, _} = result, _subject, _action, _context, _rules), do: result

  defp get_rule(_, func) when is_function(func, 3), do: func

  defp get_rule(authorizer_module, rule_name), do: export_rule(authorizer_module, rule_name)
end
