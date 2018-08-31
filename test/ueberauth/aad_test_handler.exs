defmodule Ueberauth.Strategy.AADTestHandler do
  use Ueberauth.Strategy.AAD.Handler

  @impl true
  def credentials(conn) do
    token = conn.private.aad_token

    %Credentials{token: token.token, other: %{handler: true}}
  end

  @impl true
  def info(conn) do
    user = conn.private.aad_user

    %Info{
      name: "#{user["given_name"]} #{user["family_name"]}",
      nickname: user["nickname"],
      email: user["email"],
      location: "handler"
    }
  end

  @impl true
  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private[:aad_token],
        user: conn.private[:aad_user],
        with_handler: true
      }
    }
  end
end
