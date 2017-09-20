defmodule Ueberauth.Strategy.Verimi do

  use Ueberauth.Strategy, default_scope: "login",
    uid_field: :id,
    allowed_request_params: [
      :auth_type,
      :scope,
      :locale,
      :state,
      :display
    ]

  @redirect_uri "http://ypsilon.dev:4000/auth/verimi/callback"
  @scope "login read_basket write_basket"
  @client_id "DB"

  def handle_request!(conn) do
    authorize_url = "https://verimi.com/dipp/api/oauth/service_provider_access/#{@client_id}?redirect_uri=#{@redirect_uri}&scope=#{@scope}"
    redirect!(conn, authorize_url)
  end

  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    opts = [redirect_uri: @redirect_uri]
    client = Ueberauth.Strategy.Verimi.OAuth.get_token!([code: code], opts)
    token = client.token

    if token.access_token == nil do
      err = token.other_params["error"]
      desc = token.other_params["error_description"]
      set_errors!(conn, [error(err, desc)])
    else
      fetch_user(conn, client, token.other_params["id_token"])
    end
  end


  defp fetch_user(conn, client, id_token) do
    conn = put_private(conn, :verimi_token, client.token)
    conn = put_private(conn, :verimi_id_token, id_token)
    url = "https://verimi.com/dipp/api/query/baskets"
    {:ok, 200, _headers, body} = :hackney.request(:get, url, [{"accept", "application/json"}], "", [with_body: true])
    data = body
    |> Poison.decode!
    |> Map.put(:id_token, id_token)
    put_private(conn, :verimi_user, data)
  end

  def uid(conn) do
    conn.private.verimi_id_token
  end

end
