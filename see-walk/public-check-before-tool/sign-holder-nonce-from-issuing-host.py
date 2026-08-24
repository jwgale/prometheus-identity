import json, os, urllib.request
msg = os.environ['PROMETHEUS_CHALLENGE_MESSAGE']
path = '/tmp/prometheus-public-walk-a/holders/01M0N3YH3MNCMN1CRB7STQG8CA.secret'
body = json.dumps({'challenge_message': msg, 'holder_secret_path': path}).encode()
req = urllib.request.Request('http://127.0.0.1:18790/sign-holder-nonce', data=body, headers={'content-type': 'application/json'})
print(json.load(urllib.request.urlopen(req))['holder_proof'], end='')
