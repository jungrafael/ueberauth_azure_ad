defmodule Ueberauth.Strategy.AADTest do
  use ExUnit.Case
  use Ueberauth.Strategy

  import Mock

  alias Ueberauth.Strategy.AzureAD

  @env_values [redirect_uri: "https://example.com",
    client_id: "example_client",
    tenant: "example_tenant"]

  @mock_http_reply %{
    status_code: 200,
    body: ~s(
      {
        "jwks_uri": "example_jwks_uri",
        "keys": [
          {"x5t": "7_Zuf1tvkwLxYaHS3q6lUjUYIGw", "x5c": "[x5c_example]"}
        ]
      }
    )
  }

  @user_claim %{
    claims: %{
      "email" => "user@test.com",
      "given_name" => "John",
      "family_name" => "Doe",
      "winaccountname" => "john1"
    }
  }

  describe "AAD Strategy" do
    setup_with_mocks [
      {OAuth2.Client, [:passthrough],
       [get_token: fn code, _ -> {:ok, %{token: %{access_token: code}}} end]},
      {Application, [:passthrough], [get_env: fn _, _ -> @env_values end]},
      {HTTPoison, [:passthrough], [get!: fn _ -> @mock_http_reply end]},
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

    # CLIENT
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

    # LOGOUT
    test "Handles the logout request" do
      assert AzureAD.logout(nil, nil) =~ 
      "https://login.microsoftonline.com/example_tenant/oauth2/logout?client_id=example_client"
      assert AzureAD.logout(nil) =~ 
      "https://login.microsoftonline.com/example_tenant/oauth2/logout?client_id=example_client"
    end

    test "Gives an error upon logout request with missing config" do
      with_mock Application, [:passthrough], get_env: fn _, _ -> [] end do
        assert AzureAD.logout(nil) == 
          [
            %Ueberauth.Failure.Error{
              message: "Failed to logout, please close your browser",
              message_key: "Logout Failed"
            }
          ]
      end
    end



    def build_conn do
      token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjdfWnVmMXR2a3dMeFlhSFMzcTZsVWpVWUlHdyIsImtpZCI6IjdfWnVmMXR2a3dMeFlhSFMzcTZsVWpVWUlHdyJ9"
      %Plug.Conn{params: %{"id_token" => token, "code" => "1234"}}
    end

    # CALLBACK
    test "Handle callback from AAD provider, set claims user from JWT" do
      conn = AzureAD.handle_callback!(build_conn())
      assert conn.private == @user_claim.claims
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
