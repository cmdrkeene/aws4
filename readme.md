This gem signs HTTP headers with the AWS4 signature for use with Amazon’s AWS APIs.

You MUST supply a `Date` header.

## Usage

    # create a signer
    signer = AWS4::Signer.new(
      access_key: "key",
      secret_key: "secret",
      region: "us-east-1",
      host: "dynamodb.us-east-1.amazonaws.com"
    )

    # build request
    uri = URI("https://dynamodb.us-east-1.amazonaws.com/")
    headers = {
      "Date" => "Mon, 09 Sep 2011 23:36:00 GMT",
      "Content-Type" => "application/json; charset=utf8"
    }
    body="{}"

    # sign headers
    headers = signer.sign("POST", uri, headers, body)

    # send request using library of choice

