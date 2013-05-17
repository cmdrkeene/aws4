# encoding: UTF-8
require "openssl"
require "time"
require "uri"
require "pathname"

module AWS4
  class Signer
    RFC8601BASIC = "%Y%m%dT%H%M%SZ"
    attr_reader :access_key, :secret_key, :region
    attr_reader :date, :method, :uri, :headers, :body, :service

    def initialize(config)
      @access_key = config[:access_key] || config["access_key"]
      @secret_key = config[:secret_key] || config["secret_key"]
      @region = config[:region] || config["region"]
    end

    def sign(method, uri, headers, body, debug = false)
      @method = method.upcase
      @uri = uri
      @headers = headers
      @body = body
      @service = @uri.host.split(".", 2)[0]
      date_header = headers["Date"] || headers["DATE"] || headers["date"]
      @date = (date_header ? Time.parse(date_header) : Time.now).utc.strftime(RFC8601BASIC)
      dump if debug
      signed = headers.dup
      signed['Authorization'] = authorization(headers)
      signed
    end

    private

    def authorization(headers)
      [
        "AWS4-HMAC-SHA256 Credential=#{access_key}/#{credential_string}",
        "SignedHeaders=#{headers.keys.map(&:downcase).sort.join(";")}",
        "Signature=#{signature}"
      ].join(', ')
    end

    def signature
      k_date = hmac("AWS4" + secret_key, date[0,8])
      k_region = hmac(k_date, region)
      k_service = hmac(k_region, service)
      k_credentials = hmac(k_service, "aws4_request")
      hexhmac(k_credentials, string_to_sign)
    end

    def string_to_sign
      [
        'AWS4-HMAC-SHA256',
        date,
        credential_string,
        hexdigest(canonical_request)
      ].join("\n")
    end

    def credential_string
      [
        date[0,8],
        region,
        service,
        "aws4_request"
      ].join("/")
    end

    def canonical_request
      [
        method,
        Pathname.new(uri.path).cleanpath.to_s,
        uri.query,
        headers.sort.map {|k, v| [k.downcase,v.strip].join(':')}.join("\n") + "\n",
        headers.sort.map {|k, v| k.downcase}.join(";"),
        hexdigest(body || '')
      ].join("\n")
    end

    def hexdigest(value)
      Digest::SHA256.new.update(value).hexdigest
    end

    def hmac(key, value)
      OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new('sha256'), key, value)
    end

    def hexhmac(key, value)
      OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new('sha256'), key, value)
    end

    def dump
      puts "string to sign"
      puts string_to_sign
      puts "canonical_request"
      puts canonical_request
      puts "authorization"
    end
  end
end
