require "sinatra"
require "base64"
require "json"

post "/restore" do
  state = Marshal.load(Base64.decode64(params[:state]))
  state.inspect
end

post "/import" do
  data = JSON.parse(request.body.read)
  data.keys.join(",")
end

get "/health" do
  "ok"
end
