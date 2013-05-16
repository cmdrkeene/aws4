# encoding: UTF-8
require 'minitest/spec'
require 'minitest/autorun'
require 'aws4/signature'
require "benchmark"

describe "benchmark" do
  it "runs quickly" do
    trials = 10_000
    signature = AWS4::Signature.new(
      access_key: "AKIDEXAMPLE",
      secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
      region: "us-east-1",
      host: "host.foo.com"
    )
    uri = URI("http://host.foo.com/")
    headers = {
      "Host" => "host.foo.com",
      "Date" => "Mon, 09 Sep 2011 23:36:00 GMT",
      "Content-Type" => "application/x-www-form-urlencoded; charset=utf8"
    }
    body = "foo=bar"

    t = Benchmark.realtime do
      trials.times do
        signed = signature.sign("POST", uri, headers, body)
      end
    end
    puts "#{(trials/t).round(1)} signatures/second (#{((t/trials.to_f)*1000).round(3)}ms/signature)"
  end
end
