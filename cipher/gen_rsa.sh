#equivalent to gen_rsa.go, but in bash
mkdir -p keys
openssl genrsa -out keys/private.pem 512
openssl rsa -in keys/private.pem -pubout > keys/public.pem