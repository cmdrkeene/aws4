require 'minitest/spec'
require 'minitest/autorun'
require 'aws4/signature'
require 'net/http'
require 'uri'

describe AWS4::Signature do
  def signature
    @signature ||= AWS4::Signature.new(
      access_key: "AKIDEXAMPLE",
      secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
      region: "us-east-1",
      host: "host.foo.com"
    )
  end

  it "signs get-vanilla" do
    uri = URI("http://host.foo.com/")
    headers = {
      "Host" => "host.foo.com",
      "Date" => "Mon, 09 Sep 2011 23:36:00 GMT"
    }
    body = ""
    signed = signature.sign("GET", uri, headers, body)
    signed["Date"].must_equal("Mon, 09 Sep 2011 23:36:00 GMT")
    signed["Host"].must_equal("host.foo.com")
    signed["Authorization"].must_equal("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=b27ccfbfa7df52a200ff74193ca6e32d4b48b8856fab7ebf1c595d0670a7e470")
  end

  it "signs post-vanilla" do
    uri = URI("http://host.foo.com/")
    headers = {
      "Host" => "host.foo.com",
      "Date" => "Mon, 09 Sep 2011 23:36:00 GMT"
    }
    body = ""
    signed = signature.sign("POST", uri, headers, body)
    signed["Date"].must_equal("Mon, 09 Sep 2011 23:36:00 GMT")
    signed["Host"].must_equal("host.foo.com")    
    signed["Authorization"].must_equal("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=22902d79e148b64e7571c3565769328423fe276eae4b26f83afceda9e767f726")    
  end
end
