#!/usr/bin/env bats

@test "Accept a pod without secrets" {
	run kwctl run  --request-path test_data/pod_creation_without_secrets.json  annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
 }

@test "Reject pod with secrets" {
	run kwctl run  --request-path test_data/pod_creation_with_secrets.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
	[ $(expr "$output" : '.*"message":"The following secrets were found in environment variables.*') -ne 0 ]
	[ $(expr "$output" : '.*container: nginx, key: email, reason: Email address.*') -ne 0 ]
	[ $(expr "$output" : '.*container: nginx, key: rsa, reason: RSA private key.*') -ne 0 ]
 }

 @test "Reject pod with secrets in base64" {
 	run kwctl run  --request-path test_data/pod_creation_with_secrets_base64.json annotated-policy.wasm
 	[ "$status" -eq 0 ]
 	echo "$output"
 	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
 	[ $(expr "$output" : '.*"message":"The following secrets were found in environment variables.*') -ne 0 ]
 	[ $(expr "$output" : '.*container: nginx, key: rsa, reason: RSA private key.*') -ne 0 ]
  }

@test "Reject pod with secrets in init and ephemeral containers" {
	run kwctl run  --request-path test_data/pod_creation_with_secrets_init_and_ephemeral_containers.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
	[ $(expr "$output" : '.*"message":"The following secrets were found in environment variables.*') -ne 0 ]
	[ $(expr "$output" : '.*container: busybox, key: email, reason: Email address.*') -ne 0 ]
	[ $(expr "$output" : '.*container: nginx, key: rsa, reason: RSA private key.*') -ne 0 ]
 }
