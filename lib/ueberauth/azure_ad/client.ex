defmodule Ueberauth.Strategy.AzureAD.Client do
  @moduledoc """
  Oauth2 client for Azure Active Directory.
  """

  alias OAuth2.Client
  alias OAuth2.Strategy.AuthCode
  alias Ueberauth.Strategy.AzureAD.NonceStore
  @timeout 15 * 60 * 1000 # 15 minutes

  def logout_url() do
    configset = config()
    tenant = configset[:tenant]
    tenant_name = configset[:tenant]
    |> String.split(".")
    |> List.first

    client_id = configset[:client_id]
    "https://#{tenant_name}.b2clogin.com/#{configset[:tenant]}/oauth2/v2.0/logout?client_id=#{client_id}"
  end

  def authorize_url!(callback_url) do
    params = %{
      p: "B2C_1_Customer1_SigUpOrSigIn",
      scope: "openid",
      prompt: "login",
      response_mode: "query",
      response_type: "code id_token",
      #nonce: NonceStore.create_nonce(@timeout)
      nonce: "defaultNonce"
    }

    callback_url
    |> build_client
    |> Client.authorize_url!(params)
  end

  def authorize_url(client, params) do
    AuthCode.authorize_url(client, params)
  end

  defp build_client(callback_url) do
    configset = config()

    tenant_name = configset[:tenant]
    |> String.split(".")
    |> List.first

    Client.new([
      strategy: __MODULE__,
      client_id: configset[:client_id],
      redirect_uri: callback_url,
      authorize_url: "https://#{tenant_name}.b2clogin.com/#{configset[:tenant]}/oauth2/v2.0/authorize",
      token_url: "https://#{tenant_name}.b2clogin.com/#{configset[:tenant]}/oauth2/v2.0/token"
    ])
  end

  def configured? do
    configset = config()
    configset != nil
    && Keyword.has_key?(configset, :tenant)
    && Keyword.has_key?(configset, :client_id)
  end

  defp config do
    Application.get_env(:ueberauth, Ueberauth.Strategy.AzureAD)
  end
end
