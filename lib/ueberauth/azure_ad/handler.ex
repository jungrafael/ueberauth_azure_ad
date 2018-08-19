defmodule Ueberauth.Strategy.AzureAD.Handler do
  alias Ueberauth.Auth.{Info, Credentials, Extra}
  @moduledoc """
  AzureAD Handler behaviour.

  ```elixir
  defmodule MyApp.AzureADHandler do
    use Ueberauth.Strategy.AzureAD.Handler
  end
  ```
  """

  @doc """
  Provides a place within the Ueberauth.Auth struct for information about the user.
  """
  @callback info(Plug.Conn.t()) :: %Info{}
  @doc """
  Provides information about the credentials of a request
  """
  @callback credentials(Plug.Conn.t()) :: %Credentials{}
  @doc """
  Provides a place for all raw information that was accumulated during the processing of the callback phase.
  """
  @callback extra(Plug.Conn.t()) :: %Extra{}

  defmacro __using__(_) do
    quote location: :keep do
      @behaviour Ueberauth.Strategy.AzureAD.Handler

      alias Ueberauth.Auth.{Info, Credentials, Extra}

      def credentials(conn) do
        token = conn.private.aad_token

        %Credentials{token: token.token}
      end

      def info(conn) do
        user = conn.private.aad_user

        %Info{
          name: "#{user["given_name"]} #{user["family_name"]}",
          nickname: user["winaccountname"],
          email: user["email"]
        }
      end

      def extra(conn) do
        %Extra{
          raw_info: %{
            token: conn.private[:token],
            user: conn.private[:user]
          }
        }
      end

      defoverridable Ueberauth.Strategy.AzureAD.Handler
    end
  end
end
