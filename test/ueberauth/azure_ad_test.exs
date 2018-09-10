defmodule Ueberauth.Strategy.AADTest do
  use ExUnit.Case
  use Ueberauth.Strategy

  import Mock

  alias Ueberauth.Strategy.AzureAD
  alias Ueberauth.Strategy.AzureAD.Callback

  @env_values [redirect_uri: "https://example.com",
    client_id: "example_client",
    tenant: "example_tenant"]

  describe "AAD Strategy" do
    setup_with_mocks [
      {OAuth2.Client, [:passthrough],
       [get_token: fn code, _ -> {:ok, %{token: %{access_token: code}}} end]},
      {Application, [:passthrough], [get_env: fn _, _ -> @env_values end]},
      {Ueberauth.Strategy.Helpers, [:passthrough],
       [
         callback_url: fn _ -> "https://test.com" end,
         options: fn _ -> [uid_field: "email"] end,
         redirect!: fn _conn, auth_url -> auth_url end,
         set_errors!: fn _conn, errors -> errors end
       ]},
      {SecureRandom, [:passthrough], [uuid: fn -> "example_nonce" end]},
      {:public_key, [:passthrough], [pem_decode: fn _ -> [nil] end]},
    ] do
      :ok
    end

    # CLIENT
    test "Handles the AAD request" do
      request = AzureAD.handle_request!(%Plug.Conn{params: %{}})
      assert request =~ 
        "https://login.microsoftonline.com/example_tenant/oauth2/authorize?"
        <> "client_id=example_client&"
        <> "nonce=example_nonce&"
        <> "redirect_uri=https%3A%2F%2Ftest.com&"
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

    # CALLBACK
    test "Handle callback with no errors, set user claims" do
      conn = %Plug.Conn{private: %{}, params: %{"id_token" => :id_token, "code" => :code}}

      with_mock Callback, [:passthrough], process_callback!: fn _, _ -> :claims end do
        conn = AzureAD.handle_callback!(conn)
        assert conn.private == %{aad_user: :claims}
      end
    end

    test "Handle callback processing error" do
      conn = %Plug.Conn{private: %{}, params: %{"id_token" => :id_token, "code" => :code}}

      with_mock Callback, [:passthrough], process_callback!: fn _, _ -> raise("error") end do
        error = AzureAD.handle_callback!(conn)

        assert error == 
		  %Ueberauth.Failure.Error{
			message: "error",
			message_key: "failed_auth_callback"
		  }
      end
    end

    test "Handle callback with errors" do
      conn = %Plug.Conn{params: %{"error" => "error", "error_description" => "error_description"}}
      error = AzureAD.handle_callback!(conn)
      assert error == 
        %Ueberauth.Failure.Error{
          message_key: "error",
          message: "error_description"
        }
    end

    test "Handle callback with missing code or id_token" do
      conn = %Plug.Conn{}
      error = AzureAD.handle_callback!(conn)
      assert error == 
        %Ueberauth.Failure.Error{
          message: "Missing code or id_token",
          message_key: "missing_code_or_token"
        }
    end

    @tag :skip
    test "Handle cleanup of the private vars in the conn" do
    end
  end
end
