# encoding: UTF-8
require 'minitest/spec'
require 'minitest/autorun'
require 'aws4/signature'

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

  it "signs get-vanilla-empty-query" do
    uri = URI("http://host.foo.com/?foo=bar")
    headers = {
      "Host" => "host.foo.com",
      "Date" => "Mon, 09 Sep 2011 23:36:00 GMT"
    }
    body = ""
    signed = signature.sign("GET", uri, headers, body)
    signed["Date"].must_equal("Mon, 09 Sep 2011 23:36:00 GMT")
    signed["Host"].must_equal("host.foo.com")
    signed["Authorization"].must_equal("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=56c054473fd260c13e4e7393eb203662195f5d4a1fada5314b8b52b23f985e9f")
  end

  it "signs get-unreserved" do
    uri = URI("http://host.foo.com/-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
    headers = {
      "Host" => "host.foo.com",
      "Date" => "Mon, 09 Sep 2011 23:36:00 GMT"
    }
    body = ""
    signed = signature.sign("GET", uri, headers, body)
    signed["Date"].must_equal("Mon, 09 Sep 2011 23:36:00 GMT")
    signed["Host"].must_equal("host.foo.com")
    signed["Authorization"].must_equal("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=830cc36d03f0f84e6ee4953fbe701c1c8b71a0372c63af9255aa364dd183281e")
  end

  it "signs get-vanilla-query-order" do
    uri = URI("http://host.foo.com/?foo=Zoo&foo=aha")
    headers = {
      "Host" => "host.foo.com",
      "Date" => "Mon, 09 Sep 2011 23:36:00 GMT"
    }
    body = ""
    signed = signature.sign("GET", uri, headers, body)
    signed["Date"].must_equal("Mon, 09 Sep 2011 23:36:00 GMT")
    signed["Host"].must_equal("host.foo.com")
    signed["Authorization"].must_equal("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=be7148d34ebccdc6423b19085378aa0bee970bdc61d144bd1a8c48c33079ab09")
  end

  it "signs get-vanilla-utf8-query" do
    uri = URI(URI::encode("http://host.foo.com/?ሴ=bar"))
    headers = {
      "Host" => "host.foo.com",
      "Date" => "Mon, 09 Sep 2011 23:36:00 GMT"
    }
    body = ""
    signed = signature.sign("GET", uri, headers, body)
    signed["Date"].must_equal("Mon, 09 Sep 2011 23:36:00 GMT")
    signed["Host"].must_equal("host.foo.com")
    signed["Authorization"].must_equal("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=6fb359e9a05394cc7074e0feb42573a2601abc0c869a953e8c5c12e4e01f1a8c")
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

  it "signs post-header-key-sort" do
    uri = URI("http://host.foo.com/")
    headers = {
      "Host" => "host.foo.com",
      "Date" => "Mon, 09 Sep 2011 23:36:00 GMT",
      "ZOO"  => "zoobar"
    }
    body = ""
    signed = signature.sign("POST", uri, headers, body)
    signed["Date"].must_equal("Mon, 09 Sep 2011 23:36:00 GMT")
    signed["Host"].must_equal("host.foo.com")    
    signed["Authorization"].must_equal("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host;zoo, Signature=b7a95a52518abbca0964a999a880429ab734f35ebbf1235bd79a5de87756dc4a")
  end

  it "signs post-header-key-case" do
    uri = URI("http://host.foo.com/")
    headers = {
      "Host" => "host.foo.com",
      "DATE" => "Mon, 09 Sep 2011 23:36:00 GMT"
    }
    body = ""
    signed = signature.sign("POST", uri, headers, body)
    signed["DATE"].must_equal("Mon, 09 Sep 2011 23:36:00 GMT")
    signed["Host"].must_equal("host.foo.com")    
    signed["Authorization"].must_equal("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=22902d79e148b64e7571c3565769328423fe276eae4b26f83afceda9e767f726")
  end

  it "signs post-header-value-case" do
    uri = URI("http://host.foo.com/")
    headers = {
      "Host" => "host.foo.com",
      "Date" => "Mon, 09 Sep 2011 23:36:00 GMT",
      "zoo" => "ZOOBAR"
    }
    body = ""
    signed = signature.sign("POST", uri, headers, body)
    signed["Date"].must_equal("Mon, 09 Sep 2011 23:36:00 GMT")
    signed["Host"].must_equal("host.foo.com")    
    signed["Authorization"].must_equal("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host;zoo, Signature=273313af9d0c265c531e11db70bbd653f3ba074c1009239e8559d3987039cad7")
  end

  it "signs post-x-www-form-urlencoded" do
    uri = URI("http://host.foo.com/")
    headers = {
      "Host" => "host.foo.com",
      "Date" => "Mon, 09 Sep 2011 23:36:00 GMT",
      "Content-Type" => "application/x-www-form-urlencoded"
    }
    body = "foo=bar"
    signed = signature.sign("POST", uri, headers, body)
    signed["Date"].must_equal("Mon, 09 Sep 2011 23:36:00 GMT")
    signed["Host"].must_equal("host.foo.com")    
    signed["Content-Type"].must_equal("application/x-www-form-urlencoded")
    signed["Authorization"].must_equal("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=content-type;date;host, Signature=5a15b22cf462f047318703b92e6f4f38884e4a7ab7b1d6426ca46a8bd1c26cbc")
  end

  it "signs post-x-www-form-urlencoded-parameters" do
    uri = URI("http://host.foo.com/")
    headers = {
      "Host" => "host.foo.com",
      "Date" => "Mon, 09 Sep 2011 23:36:00 GMT",
      "Content-Type" => "application/x-www-form-urlencoded; charset=utf8"
    }
    body = "foo=bar"
    signed = signature.sign("POST", uri, headers, body)
    signed["Date"].must_equal("Mon, 09 Sep 2011 23:36:00 GMT")
    signed["Host"].must_equal("host.foo.com")    
    signed["Content-Type"].must_equal("application/x-www-form-urlencoded; charset=utf8")
    signed["Authorization"].must_equal("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=content-type;date;host, Signature=b105eb10c6d318d2294de9d49dd8b031b55e3c3fe139f2e637da70511e9e7b71")
  end
end
