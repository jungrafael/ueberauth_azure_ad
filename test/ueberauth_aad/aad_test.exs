defmodule Ueberauth.Strategy.AADTest do
  use ExUnit.Case
  use Ueberauth.Strategy

  import Mock

  alias Ueberauth.Strategy.AAD

  describe "AAD Strategy" do
    test "Handles the AAD request" do
    end

    test "Redirects AAD request to index when missing config" do
    end

    test "Handles the logout request" do
    end

    test "Gives an error upon logout request with missing config" do
    end

    test "Handle callback from AAD provider, set claims user from JWT" do
    end

    test "Handle callback from AAD provider when JWT is unauthorized" do
    end

    test "Handle callback from AAD provider when metadata is malformed" do
    end

    test "Handle callback from AAD provider when certificate is not found in metadata" do
    end

    test "Handle callback from AAD provider when metadata url is not found" do
    end

    test "Handle callback from AAD provider with token error" do
    end

    test "Handle callback from AAD provider with OAuth2 error" do
    end

    test "Handle callback from AAD provider with error in the params" do
    end

    test "Handle callback from AAD provider with missing code" do
    end

    test "Handles cleanup of the private vars in the conn" do
    end

    test "Gets the uid field from the conn" do
    end

    test "Gets the token credentials from the conn" do
    end

    test "Gets the user info from the conn" do
    end

    test "Gets the extra info from the conn" do
    end

    test "Gets the credential info from the conn with a custom handler" do
    end

    test "Gets the user info from the conn with a custom handler" do
    end

    test "Gets the extra info from the conn with a custom handler" do
    end

    test "Returns the configured status when env is present" do
    end

    test "Returns the configured status when env is not present" do
    end

    test "Returns the configured status when env is missing values" do
    end
  end

  describe "AAD Oauth Client" do
    test "Gets the client with the config properties" do
    end

    test "Gets the client with options" do
    end

    test "Doesn't get the client without config" do
    end

    test "Get the authorize_url" do
    end

    test "Gets the signout url" do
    end

    test "Gets the signout url with params" do
    end

    test "Fails to get the signout url without config" do
    end
  end
end
