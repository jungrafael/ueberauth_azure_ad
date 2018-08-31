defmodule Ueberauth.Strategy.AzureAD do
  @moduledoc """
  """

  use Ueberauth.Strategy
  alias Ueberauth.Strategy.AzureAD.Client
  alias Ueberauth.Strategy.AzureAD.Callback

  def handle_request!(conn) do
    if Client.configured? do
      url = Client.authorize_url!()
      redirect!(conn, external: url)
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
    %Plug.Conn{params: %{"id_token" => id_token, "code" => code}} = conn
  ) do
    claims = Callback.process_callback!(id_token, code)
    put_private(conn, :aad_user, claims)
  end

  def handle_callback!(
        %Plug.Conn{params: %{"error" => error, "error_description" => error_description}} = conn
      ) do
    set_errors!(conn, [error(error, error_description)])
  end

  def handle_callback!(conn) do
    IO.inspect conn
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
