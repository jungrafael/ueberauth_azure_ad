defmodule Ueberauth.Strategy.AzureAD.Callback do
  @moduledoc """
  Provides the callback functions for Azure Active directory Oauth.
  The public keys from the Microsoft openid configuration are fetched, and the appropriate key is
  selected using the kid value from the returned token header. The public key is used to verify the
  token and then the returned code is used to verify the claims on the token.
  """

  alias JsonWebToken.Algorithm.RsaUtil
  alias Ueberauth.Strategy.AzureAD.VerifyClaims
  alias Ueberauth.Strategy.AzureAD.Enforce

  def process_callback!(id_token, code) do
    id_token
    |> get_claims_from_id_token
    |> VerifyClaims.verify!(code)
  end

  def get_claims_from_id_token(id_token) do
    public_key = id_token |> get_public_key_from_id_token

    opts = %{
      alg: "RS256",
      key: public_key
    }

    id_token
    |> JsonWebToken.verify(opts)
    |> Enforce.ok!("JWT verification failed")
  end

  defp get_public_key_from_id_token(id_token) do
    id_token
    |> get_kid_from_token!
    |> get_public_key
  end

  defp get_kid_from_token!(id_token) do
    error = "Failed to get kid from token - invalid response"

    id_token
    # get token header
    |> String.split(".")
    |> List.first
    # decode
    |> Base.url_decode64(padding: false)
    |> Enforce.ok!(error)
    |> Jason.decode
    |> Enforce.ok!(error)
    # get kid
    |> Map.get("kid")
  end

  defp get_public_key(kid) do
    jwks_uri!()
    |> get_discovery_keys!(kid)
    |> get_public_key_from_cert
    |> RsaUtil.public_key
  end

  defp jwks_uri! do
    configset = config()

    tenant_name = configset[:tenant]
    |> String.split(".")
    |> List.first

    "https://#{tenant_name}.b2clogin.com/#{configset[:tenant]}/v2.0/.well-known/openid-configuration?p=#{configset[:authorization_p]}"
    |> http_request!
    |> Jason.decode
    |> Enforce.ok!("Failed to retrieve jwks uri - invalid response")
    |> Map.get("jwks_uri")
  end

  defp get_discovery_keys!(url, kid)do
    url
    |> http_request!
    |> Jason.decode
    |> Enforce.ok!("Failed to retrieve discovery keys - invalid response")
    |> Map.get("keys")
    |> Enum.filter(fn(key) -> key["kid"] === kid end)
    |> List.first
  end

  # always use the first kid value
  defp get_public_key_from_cert(cert_data) do
    case System.cmd("node", ["pemFromModExpo.js", cert_data["n"], cert_data["e"]], cd: :code.priv_dir(:ueberauth_azure_ad) |> List.to_string) do
      {output, 0} -> {:ok, output}
      _           -> :error
    end
    |> Enforce.ok!("Failed to retrieve public key - invalid response")
  end

  defp http_request!(url) do
    case HTTPoison.get(url) do
      {:ok, %HTTPoison.Response{status_code: 200, body: body}} ->
        body
      {:ok, %HTTPoison.Response{status_code: code}} ->
        raise "HTTP request error. Status Code: #{code} URL: #{url}"
      {:error, error} ->
        raise error
    end
  end

  defp config do
    Application.get_env(:ueberauth, Ueberauth.Strategy.AzureAD)
  end
end
