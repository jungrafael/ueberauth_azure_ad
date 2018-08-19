defmodule Ueberauth.Strategy.AzureAD do
  @moduledoc """
  """

  alias Ueberauth.Strategy.AzureAD.Client
  alias Ueberauth.Strategy.AzureAD.Callback

  def handle_request!(conn) do
    if Client.configured?() do
      # TODO redirect_to_authorization(conn)
    else
      redirect!(conn, "/")
    end
  end

  def logout(conn, token) do
    logout_url = Client.logout_url(callback_url(conn), token)

    with {:ok, logout_url} <- logout_url do
      redirect!(conn, logout_url)
    else
      _ ->
        set_errors!(conn, [error("Logout Failed", "Failed to logout, please close your browser")])
    end
  end

  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    # TODO use Callback?
    with {:ok, client} <- OAuth.get_token(code, redirect_uri: callback_url(conn)) do
      # TODO fetch_user(conn, client)
    else
      {:error, %{reason: reason}} ->
        set_errors!(conn, [error("Authentication Error", reason)])

      {:error, %OAuth2.Response{body: %{"error_description" => reason}}} ->
        set_errors!(conn, [error("Authentication Error", reason)])
    end
  end

  def handle_callback!(
        %Plug.Conn{params: %{"error" => error, "error_description" => error_description}} = conn
      ) do
    set_errors!(conn, [error(error, error_description)])
  end

  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  def handle_cleanup!(conn) do
    conn
    |> put_private(:aad_user, nil)
    |> put_private(:aad_token, nil)
    |> put_private(:aad_handler, nil)
  end

  def uid(conn) do
    # TODO is uid correct?
    uid_field =
      conn
      |> option(:uid_field)
      |> to_string

    conn.private.aad_user[uid_field]
  end

  def credentials(conn) do
    apply(conn.private.aad_handler, :credentials, [conn])
  end

  def info(conn) do
    apply(conn.private.aad_handler, :info, [conn])
  end

  def extra(conn) do
    apply(conn.private.aad_handler, :extra, [conn])
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end
end
