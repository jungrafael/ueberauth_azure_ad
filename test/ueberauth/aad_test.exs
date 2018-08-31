defmodule Ueberauth.Strategy.AADTest do
  use ExUnit.Case
  use Ueberauth.Strategy

  import Mock

  alias Ueberauth.Strategy.AzureAD

  @env_values %{
    redirect_uri: "https://example.com",
    client_id: "example_client",
    tenant: "example_tenant",
  }

  @mock_metadata nil

  describe "AAD Strategy" do
    setup_with_mocks [
      {OAuth2.Client, [:passthrough],
       [get_token: fn code, _ -> {:ok, %{token: %{access_token: code}}} end]},
      {Application, [:passthrough], [get_env: fn _, _ -> @env_values end]},
      {HTTPoison, [:passthrough], [get: fn _, _, _ -> @mock_metadata end]},
      {SecureRandom, [:passthrough], [uuid: fn -> "example_nonce" end]},
      {Ueberauth.Strategy.Helpers, [:passthrough],
       [
         callback_url: fn _ -> "https://test.com" end,
         options: fn _ -> [uid_field: "email"] end,
         redirect!: fn _conn, auth_url -> auth_url end,
         set_errors!: fn _conn, errors -> errors end
       ]}
    ] do
      :ok
    end

    test "Handles the AAD request" do
      [external: request] = AzureAD.handle_request!(%Plug.Conn{params: %{}})
      assert request =~ 
        "https://login.microsoftonline.com/example_tenant/oauth2/authorize?"
        <> "client_id=example_client&"
        <> "nonce=example_nonce&"
        <> "redirect_uri=https%3A%2F%2Fexample.com&"
        <> "response_mode=form_post&"
        <> "response_type=code+id_token"
    end

    test "Redirects AAD request to index when missing config" do
      with_mock Application, [:passthrough], get_env: fn _, _ -> nil end do
        assert AzureAD.handle_request!(nil) == "/"
      end
    end

    @tag :skip
    test "Handles the logout request" do
    end

    @tag :skip
    test "Gives an error upon logout request with missing config" do
    end

    @tag :skip
    test "Handle callback from AAD provider, set claims user from JWT" do
    end

    @tag :skip
    test "Handle callback from AAD provider when JWT is unauthorized" do
    end

    @tag :skip
    test "Handle callback from AAD provider when metadata is malformed" do
    end

    @tag :skip
    test "Handle callback from AAD provider when certificate is not found in metadata" do
    end

    @tag :skip
    test "Handle callback from AAD provider when metadata url is not found" do
    end

    @tag :skip
    test "Handle callback from AAD provider with token error" do
    end

    @tag :skip
    test "Handle callback from AAD provider with OAuth2 error" do
    end

    @tag :skip
    test "Handle callback from AAD provider with error in the params" do
    end

    @tag :skip
    test "Handle callback from AAD provider with missing code" do
    end

    @tag :skip
    test "Handles cleanup of the private vars in the conn" do
    end

    @tag :skip
    test "Gets the uid field from the conn" do
    end

    @tag :skip
    test "Gets the token credentials from the conn" do
    end

    @tag :skip
    test "Gets the user info from the conn" do
    end

    @tag :skip
    test "Gets the extra info from the conn" do
    end

    @tag :skip
    test "Gets the credential info from the conn with a custom handler" do
    end

    @tag :skip
    test "Gets the user info from the conn with a custom handler" do
    end

    @tag :skip
    test "Gets the extra info from the conn with a custom handler" do
    end

    @tag :skip
    test "Returns the configured status when env is present" do
    end

    @tag :skip
    test "Returns the configured status when env is not present" do
    end

    @tag :skip
    test "Returns the configured status when env is missing values" do
    end
  end

  describe "AAD Oauth Client" do
    @tag :skip
    test "Gets the client with the config properties" do
    end

    @tag :skip
    test "Gets the client with options" do
    end

    @tag :skip
    test "Doesn't get the client without config" do
    end

    @tag :skip
    test "Get the authorize_url" do
    end

    @tag :skip
    test "Gets the signout url" do
    end

    @tag :skip
    test "Gets the signout url with params" do
    end

    @tag :skip
    test "Fails to get the signout url without config" do
    end
  end
end
