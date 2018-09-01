defmodule Ueberauth.Strategy.AzureAD do
  @moduledoc """
  """

  use Ueberauth.Strategy
  alias Ueberauth.Strategy.AzureAD.Client
  alias Ueberauth.Strategy.AzureAD.Callback
  require Logger
  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra

  def handle_request!(conn) do
    if Client.configured? do
      callback_url = callback_url(conn)
      url = Client.authorize_url!(callback_url)
      redirect!(conn, url)
    else
      redirect!(conn, "/")
    end
  end

  def logout(conn, _token), do: logout(conn)
  def logout(conn) do
    if Client.configured? do
      redirect!(conn, Client.logout_url())
    else
      set_errors!(conn, [error("Logout Failed", "Failed to logout, please close your browser")])
    end
  end

  def handle_callback!(
    %{params: %{"id_token" => id_token, "code" => code}} = conn
  ) do
    try do
      claims = Callback.process_callback!(id_token, code)
      put_private(conn, :aad_user, claims)
    rescue
      e in RuntimeError -> 
        set_errors!(conn, [error("failed_auth_callback", e.message)])
    end
  end

  def handle_callback!(
    %Plug.Conn{params: %{"error" => error, "error_description" => error_description}} = conn
  ) do
    set_errors!(conn, [error(error, error_description)])
  end

  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code_or_token", "Missing code or id_token")])
  end

  def handle_cleanup!(conn) do
    # TODO I'm not sure that this does it's job properly
    conn
    |> put_private(:aad_user, nil)
  end

  def uid(conn) do
    conn.private.aad_user.oid
  end

  def credentials(conn) do
    struct(
      Credentials,
      other: %{
        id_token: conn.params["id_token"],
        code: conn.params["code"],
      }
    )
  end

  def info(conn) do
    claims = conn.private.aad_user
    nickname = get_name(conn.private.aad_user)
    
    struct(
      Info,
      email: Map.get(claims, :email),
      name: Map.get(claims, :name),
      first_name: Map.get(claims, :given_name),
      last_name: Map.get(claims, :family_name),
      nickname: nickname,
      # it isn't in the documentation,
      # but I'm sure I've seen :phone in the claims before
      phone: Map.get(claims, :phone)
    )
  end

  def extra(conn) do
    struct(Extra, raw_info: conn.params)
  end

  defp get_name(map) do
    cond do
      map[:username] -> format_name(map[:username])
      map[:upn] -> format_name(map[:upn])
      map[:unique_name] -> format_name(map[:unique_name])
      map[:name] -> format_name(map[:name])
      map[:email] -> format_name(map[:email])
      true -> nil
    end
  end

  defp format_name(name) do
    name
      |> String.split(["@", "_"])
      |> hd
      |> String.split(".")
      |> Enum.map(&String.capitalize/1)
      |> Enum.join(" ")
  end
end
