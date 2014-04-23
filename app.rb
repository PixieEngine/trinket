require "base64"
require "digest/sha1"
require "json"
require "openssl"
require "pry" if ENV["RACK_ENV"] == "development"
require "sinatra"
require "sinatra_auth_github"
require "unf"

require "rack/cors"

use Rack::Cors do |config|
  config.allow do |allow|
    allow.origins '*'
    allow.resource '*',
      :headers => :any
  end
end

enable :sessions

register Sinatra::Auth::Github

configure do
  set :github_options, {
    :scopes    => "gist",
    :secret    => ENV['GITHUB_CLIENT_SECRET'],
    :client_id => ENV['GITHUB_CLIENT_ID'],
  }

  set :aws_access_key_id, ENV["ACCESS_KEY_ID"]
  set :aws_secret_key, ENV["SECRET_ACCESS_KEY"]

  set :bucket, ENV["AWS_BUCKET"]
end

get "/policy.json" do
  content_type :json

  authenticate!

  namespace = "#{github_user.id}/"

  max_size = 10 * 1024 * 1024 # 10 MB
  policy_document = {
    expiration: "2020-12-01T12:00:00.000Z",
    conditions: [
      { bucket: settings.bucket},
      ["starts-with", "$key", namespace],
      { acl: "public-read"},
      ["starts-with", "$Content-Type", ""],
      ["content-length-range", 0, max_size]
    ]
  }.to_json

  encoded_policy_document = Base64.encode64(policy_document).gsub("\n","")

  {
    accessKey: ENV["ACCESS_KEY_ID"],
    acl: "public-read",
    bucket: settings.bucket,
    policy: encoded_policy_document,
    signature: sign_policy(encoded_policy_document)
  }.to_json
end

def sign_policy(base64_encoded_policy_document)
  signature = Base64.encode64(
    OpenSSL::HMAC.digest(
      OpenSSL::Digest::Digest.new('sha1'),
      settings.aws_secret_key,
      base64_encoded_policy_document
    )
  ).gsub("\n","")
end
