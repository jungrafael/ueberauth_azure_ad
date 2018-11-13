defmodule Mix.Tasks.Compile.Npm do
  @moduledoc """
  Installs npm packages on compile
  """

  use Mix.Task

  def run(_args) do
    case System.cmd("npm", ["install"]) do
      {_output, 0} -> :ok
      {output, _n} -> {:error, output}
    end
  end
end
