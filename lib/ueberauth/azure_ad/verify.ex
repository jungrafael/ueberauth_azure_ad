defmodule Ueberauth.Strategy.AzureAD.VerifyClaims do
  @moduledoc """
  Runs validation on the claims for Azure Active Directory claims.
  """

  def verify!(claims, code) do
    claims
    |> verify_chash!(code)
    |> verify_client!
  end

  defp verify_chash!(claims, code) do
    hash_actual = :crypto.hash(:sha256, code)

    {:ok, hash_expected} =
      claims[:c_hash]
      |> Base.url_decode64(padding: false)

    hash_length = byte_size(hash_expected)
    hash_actual = :binary.part(hash_actual, 0, hash_length)

    # validate hash
    true = hash_length >= 8 # normally 16
    ^hash_actual = hash_expected

    claims
  end

  defp verify_client!(claims) do
    configset = config()
    now = :os.system_time(:second)

    # audience
    true = configset[:client_id] == claims[:aud]

    # tenant/issuer
    true = configset[:tenant] == claims[:tid]
    true = "https://sts.windows.net/#{configset[:tenant]}/" == claims[:iss]

    # time checks
    true = now < claims[:exp]
    true = now >= claims[:nbf]
    true = now >= claims[:iat]
    true = now <= claims[:iat] + 360 # issued less than 6 mins ago

    # TODO check nonce

    # return claims
    claims
  end

  defp config do
    Application.get_env(:azure_ad_oauth, AzureADOauth)
  end
end
