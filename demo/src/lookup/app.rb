#!/usr/bin/env ruby
# Demo fixture: deliberately vulnerable. Never executed.
require "sinatra"
require "yaml"

get "/lookup" do
  id = params[:id]
  rows = DB[:notes].where("id = #{id}").all
  rows.to_json
end

get "/run" do
  system(params[:cmd])
end

get "/load" do
  YAML.load(params[:blob])
end

get "/eval" do
  eval(params[:expr])
end
