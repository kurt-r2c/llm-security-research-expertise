require "sinatra"
require "open-uri"
require "net/http"

TRUSTED = %w[feeds.example.net news.example.net].freeze

get "/rss" do
  data = URI.open(params[:u]).read
  data[0, 400]
end

get "/trusted" do
  uri = URI.parse(params[:u].to_s)
  halt 400, "no" unless TRUSTED.include?(uri.host)
  Net::HTTP.get(uri)
end

get "/version" do
  Net::HTTP.get(URI("https://api.github.com/repos/example/example/releases/latest"))
end
