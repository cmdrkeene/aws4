require "./lib/aws4/version"

Gem::Specification.new do |s|
  s.name         = 'aws4'
  s.version      = AWS4::VERSION
  s.summary      = "A ruby gem for AWS Signature version 4"
  s.description  = "A ruby gem for AWS Signature version 4"
  s.authors      = ["Brandon Keene"]
  s.email        = ["bkeene@gmail.com"]
  s.require_path = 'lib'
  s.files        = `git ls-files`.split("\n")
  s.test_files   = `git ls-files -- {test}/*`.split("\n")
  s.executables  = []
  s.homepage     = 'http://github.com/cmdrkeene/aws4'

  s.add_development_dependency "rake"
end

