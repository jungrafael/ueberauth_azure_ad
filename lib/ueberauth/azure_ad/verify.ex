defmodule Ueberauth.Strategy.AzureAD.VerifyClaims do
  @moduledoc """
  Runs validation on the claims for Azure Active Directory claims.
  """

  alias Ueberauth.Strategy.AzureAD.Enforce

  def verify!(claims, code) do
    claims
    |> verify_chash!(code)
    |> validate_claims!
  end

  defp verify_chash!(claims, code) do
    hash_actual = :crypto.hash(:sha256, code)

    hash_expected =
      claims[:c_hash]
      |> Base.url_decode64(padding: false)
      |> Enforce.ok!("Failed to decode c_hash")

    hash_length = byte_size(hash_expected)
    hash_actual = :binary.part(hash_actual, 0, hash_length)

    # validate hash
    (hash_length >= 8) # normally 16
    |> Enforce.true!("Invalid c_hash - too short")

    (hash_actual == hash_expected)
    |> Enforce.true!("Invalid c_hash - c_hash from id_token and code do not match")

    claims
  end

  defp validate_claims!(claims) do
    configset = config()
    now = :os.system_time(:second)

    Enforce.true!([
      # audience
      {configset[:client_id] == claims[:aud], "aud"},

      # tenant/issuer
      {configset[:tenant] == claims[:tid], "tid"},
      {"https://sts.windows.net/#{configset[:tenant]}/" == claims[:iss], "iss"},

      # time checks
      {now < claims[:exp], "exp"},
      {now >= claims[:nbf], "nbf"},
      {now >= claims[:iat], "iat"},
      {now <= claims[:iat] + 360, "iat"} # issued less than 6 mins ago

      # TODO check nonce
    ], "Invalid claim: ")

    # return claims
    claims
  end

  defp config do
    Application.get_env(:ueberauth, Ueberauth.Strategy.AzureAD)
  end
end
