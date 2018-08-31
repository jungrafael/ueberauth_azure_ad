defmodule Ueberauth.Strategy.AzureAD.Callback do
  @moduledoc """
  Provides the callback functions for Azure Active directory Oauth. 
  The public keys from the Microsoft openid configuration are fetched, and the appropriate key is
  selected using the x5t value from the returned token header. The public key is used to verify the
  token and then the returned code is used to verify the claims on the token.
  """

  alias JsonWebToken.Algorithm.RsaUtil
  alias Ueberauth.Strategy.AzureAD.VerifyClaims

  def process_callback!(id_token, code) do
    x5t = get_x5t_from_token!(id_token)

    public =
      jwks_uri!()
      |> get_discovery_keys!(x5t)
      |> get_public_key
      |> RsaUtil.public_key

    opts = %{
      alg: "RS256",
      key: public
    }

    id_token
    |> JsonWebToken.verify(opts)
    |> enforce_ok!
    |> VerifyClaims.verify!(code)
  end

  defp enforce_ok!({:ok, value}) do
    value
  end

  defp get_x5t_from_token!(id_token) do
    id_token
    # get token header
    |> String.split(".")
    |> List.first
    # decode
    |> Base.url_decode64(padding: false)
    |> enforce_ok!
    |> JSON.decode
    |> enforce_ok!
    # get x5t
    |> Map.get("x5t")
  end

  defp jwks_uri! do
    "https://login.microsoftonline.com/common/.well-known/openid-configuration"
    |> http_request!
    |> JSON.decode
    |> enforce_ok!
    |> Map.get("jwks_uri")
  end

  defp http_request!(url) do
    %{status_code: 200, body: body} =
      HTTPoison.get!(url)
    body
  end

  defp get_discovery_keys!(url, x5t)do
    url
    |> http_request!
    |> JSON.decode
    |> enforce_ok!
    |> Map.get("keys")
    |> Enum.filter(fn(key) -> key["x5t"] === x5t end)
    |> List.first
    |> Map.get("x5c")
  end

  # always use the first x5t value
  # this is the function I am most worried about. Do the certificates always use this format?
  defp get_public_key([cert | _]) do
    spki =
      "-----BEGIN CERTIFICATE-----\n#{cert}\n-----END CERTIFICATE-----\n"
      |> :public_key.pem_decode
      |> hd
      |> :public_key.pem_entry_decode
      |> elem(1)
      |> elem(7)

    :public_key.pem_entry_encode(:SubjectPublicKeyInfo, spki)
    |> List.wrap
    |> :public_key.pem_encode
  end
end
