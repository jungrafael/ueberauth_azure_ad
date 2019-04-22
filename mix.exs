defmodule UeberauthAzureAD.MixProject do
  use Mix.Project

  @version "0.0.0"
  @url "https://github.com/jungrafael/ueberauth_azure_ad"
  @maintainers ["Rafael Jung"]

  def project do
    [
      app: :ueberauth_azure_ad,
      version: @version,
      elixir: "~> 1.6",
      elixirc_paths: elixirc_paths(Mix.env),
      compilers: Mix.compilers() ++ [:npm],
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "Ueberauth Azure Active Directory B2C",
      description: "Azure Active Directory Strategy for Überauth",
      source_url: @url,
      homepage_url: @url,
      package: package(),
      deps: deps(),
      docs: docs()
    ]
  end

  defp elixirc_paths(_),     do: ["lib", "node_modules"]

  def package do
    [
      maintainers: @maintainers,
      licenses: ["MIT"],
      links: %{"GitHub" => @url},
      files: ~w(lib) ++ ~w(LICENSE.md mix.exs README.md)
    ]
  end

  def docs do
    [
      extras: ["README.md", "LICENSE.md"],
      source_ref: "v#{@version}",
      main: "readme"
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :ueberauth, :oauth2]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:oauth2, "~> 0.9.2"},
      {:json_web_token, "~> 0.2.5"},
      {:jason, "~> 1.1"},
      {:secure_random, "~> 0.5"},
      {:httpoison, "~> 1.2"},
      {:ueberauth, "~> 0.5"},

      # tools
      {:mock, "~> 0.3.0", only: :test},
      {:mix_test_watch, "~> 0.8", only: :dev, runtime: false},
      {:ex_doc, ">= 0.0.0", only: :dev},
    ]
  end
end
