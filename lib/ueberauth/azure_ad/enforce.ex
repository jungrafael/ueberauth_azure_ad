defmodule Ueberauth.Strategy.AzureAD.Enforce do
  @moduledoc """
  Helper functions for enforing some conditions. The functions raise errors if the conditions
  aren't met.

  Useful for enforcing claims validation and destructuring :ok atoms without breaking the pipe.
  """

  def true!([true | rest], error), do: true!(rest, error)
  def true!([true], _), do: true
  def true!(true, _), do: true
  def true!(_, error), do: raise error

  def ok!({:ok, value}, _), do: value
  def ok!(_, error), do: raise error
end
