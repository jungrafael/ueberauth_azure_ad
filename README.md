# Überauth Azure Active Directory
[![Build Status][travis-img]][travis] [![Hex Version][hex-img]][hex] [![License][license-img]][license]

[travis-img]: https://travis-ci.org/whossname/ueberauth_identity.svg?branch=master
[travis]: https://travis-ci.org/whossname/ueberauth_azure_ad
[hex-img]: https://img.shields.io/hexpm/v/ueberauth_azure_ad.svg
[hex]: https://hex.pm/packages/ueberauth_azure_ad
[license-img]: http://img.shields.io/badge/license-MIT-brightgreen.svg
[license]: http://opensource.org/licenses/MIT

> An Azure Active Directory strategy for Überauth.

## Installation

1. Add `:ueberauth_azure_ad` to your list of dependencies in `mix.exs`:

    ```elixir
    def deps do
      [{:ueberauth_azure_ad, "~> 0.?"}]
    end
    ```

1. Add the strategy to your applications:

    ```elixir
    def application do
      [applications: [:ueberauth_azure_ad]]
    end
    ```

1. Add AzureAD to your Überauth configuration:

    ```elixir
    config :ueberauth, Ueberauth,
      providers: [
        ueberauth_azure_ad: {Ueberauth.Strategy.AzureAD,
          [
            # set to your request_path
            request_path: "/auth",
            # set to your callback_path
            callback_path: "/auth/callback",
            # Azure Active Directory uses POST for it's callback
            callback_methods: ["POST"]
          ]
        }
      ]
    ```

1. Add your client_id and tenant to the AzureAD strategy configuration:

    ```elixir
    config :ueberauth, Ueberauth.Strategy.AzureAD,
      client_id: <your client_id>,
      tenant: <your tenant>
    ```

1.  Include the Überauth plug in your controller:

    ```elixir
    defmodule MyApp.AuthController do
      use MyApp.Web, :controller
      plug Ueberauth
      ...
    end
    ```

1.  Create the request and callback routes if you haven't already:

    ```elixir
    scope "/auth", MyApp do
      pipe_through :browser

      get "/:provider", AuthController, :request
      get "/:provider/callback", AuthController, :callback
      post "/identity/callback", AuthController, :identity_callback
    end
    ```

## Credit
This repository was used as a base for the AzureAD authentication.
https://github.com/onurkucukkece/oauth_azure_activedirectory

## License

Please see [LICENSE](https://github.com/whossname/ueberauth_azure_ad/blob/master/LICENSE.md) for licensing details.

