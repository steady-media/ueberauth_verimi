defmodule Ueberauth.Strategy.Verimi.OAuth do
  use OAuth2.Strategy

  @defaults [
    strategy: __MODULE__,
    site: "https://verimi.com/dipp/api",
    authorize_url: "https://verimi.com/dipp/api/oauth/service_provider_access/",
    token_url: "https://verimi.com/dipp/api/oauth/token",
    token_method: :post
  ]

  @doc """
  Construct a client for requests to Facebook.

  This will be setup automatically for you in `Ueberauth.Strategy.Facebook`.
  These options are only useful for usage outside the normal callback phase
  of Ueberauth.
  """
  def client(opts \\ []) do
    config = Application.get_env(:ueberauth, Ueberauth.Strategy.Verimi.OAuth)

    opts =
      @defaults
      |> Keyword.merge(config)
      |> Keyword.merge(opts)

    OAuth2.Client.new(opts)
  end

  @doc """
  Provides the authorize url for the request phase of Ueberauth.
  No need to call this usually.
  """
  def authorize_url!(params \\ [], opts \\ []) do
    opts
    |> client
    |> OAuth2.Client.authorize_url!(params)
  end

  def get_token!(params \\ [], opts \\ []) do
    client = opts
    |> client

    OAuth2.Client.get_token!(client, params)
  end

  # Strategy Callbacks

  def authorize_url(client, params) do
    OAuth2.Strategy.AuthCode.authorize_url(client, params)
  end

  def get_token(client, params, headers) do
    client = client
    |> basic_auth()
    |> put_header("accept", "application/json")
    |> OAuth2.Strategy.AuthCode.get_token(params, headers)

    %{client | params: Map.delete(client.params, "client_id")}
  end
end
