require "openssl"
require "time"

module AWS4
  class Signature
    attr_reader :access_key, :secret_key, :region
    attr_reader :date, :method, :uri, :headers, :body

    def initialize(config)
      @access_key = config[:access_key] || config["access_key"]
      @secret_key = config[:secret_key] || config["secret_key"]
      @region = config[:region] || config["region"]
    end

    def sign(method, uri, headers, body)
      @method = method.upcase
      @uri = uri
      @headers = headers
      @body = body
      @date = Time.parse(headers["Date"]).utc.strftime("%Y%m%dT%H%M%SZ")
      signed = headers.dup
      signed['Authorization'] = authorization(headers)
      signed
    end

    def service
      @uri.host.split(".", 2)[0]
    end

    def authorization(headers)
      parts = []
      parts << "AWS4-HMAC-SHA256 Credential=#{access_key}/#{credential_string}"
      parts << "SignedHeaders=#{headers.keys.map(&:downcase).sort.join(";")}"
      parts << "Signature=#{signature}"
      parts.join(', ')
    end

    def signature
      k_secret = secret_key
      k_date = hmac("AWS4" + k_secret, date[0,8])
      k_region = hmac(k_date, region)
      k_service = hmac(k_region, service)
      k_credentials = hmac(k_service, 'aws4_request')
      hexhmac(k_credentials, string_to_sign)
    end

    def string_to_sign
      parts = []
      parts << 'AWS4-HMAC-SHA256'
      parts << date
      parts << credential_string
      parts << hexdigest(canonical_request)
      s = parts.join("\n")
      puts "string to sign", s
      puts
      s
    end

    def credential_string
      parts = []
      parts << date[0,8]
      parts << region
      parts << service
      parts << 'aws4_request'
      parts.join("/")
    end

    def canonical_request
      parts = []
      parts << method
      parts << uri.path + "\n"
      parts << headers.sort.map {|k, v| [k.downcase,v].join(':')}.join("\n") + "\n"
      parts << headers.sort.map {|k, v| k.downcase}.join(";")
      parts << hexdigest(body || '')
      s = parts.join("\n")
      puts "canonical request", s
      puts
      s
    end

    def hexdigest(value)
      digest = Digest::SHA256.new
      digest.update(value)
      digest.hexdigest
    end

    def hmac(key, value)
      OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new('sha256'), key, value)
    end

    def hexhmac(key, value)
      OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new('sha256'), key, value)
    end
  end
end
