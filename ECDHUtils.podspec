Pod::Spec.new do |s|
  s.name             = "ECDHUtils"
  s.summary          = "An Objective-C library for Elliptic Curve Diffie-Hellman (ECDH)."
  s.version          = "1.0"
  s.homepage         = "https://github.com/ankitthakur/GMEllipticCurveCrypto"
  s.license          = 'BSD 2-Clause License'
  s.author           = { "MFEC" => "ps-sd@mfec.co.th" }
  s.source           = {
    :git => "https://github.com/HelloCore/ECDHUtils.git",
    :tag => "v#{s.version}"
  }

  s.ios.deployment_target = '8.0'

  s.requires_arc = true
  s.source_files = 'Pod/Classes/**/*'

  s.dependency 'OpenSSL-Universal', '~> 1.0'
end